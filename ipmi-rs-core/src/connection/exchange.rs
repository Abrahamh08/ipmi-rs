//! Transport-neutral exchange of encoded requests for borrowed responses, without allocation.
//!
//! [`IpmiConnection`](super::IpmiConnection) owns its requests and responses, so it needs `alloc`. The traits here
//! instead take an [`EncodedRequest`] that borrows its data from caller storage and return a response that may borrow
//! from the transport's own buffer. A transport frames the request for its medium (IPMB, serial, RMCP) and chooses
//! whether to hand back an owned response or one that borrows from `&mut self`.
//!
//! # Reading a failed response
//!
//! [`IpmiExchange::send_recv`] reports a failed response as a [`ResponseError`]: the completion code and the
//! command's own error, but not the raw response data. A transport whose [`IpmiExchange::Response`] borrows from the
//! transport cannot have that data in the error, because the error would keep the transport borrowed until it was
//! dropped. A transport that returns an owned response does not have that restriction.
//!
//! To read the data in either case, exchange and parse in two steps. A borrowed response must be dropped before the
//! next exchange:
//!
//! ```
//! use ipmi_rs_core::{
//!     app::GetChannelInfo,
//!     connection::{
//!         Channel, EncodeIpmiCommand, EncodedRequest, IpmiExchange, IpmiResponseView, NetFn, parse_response,
//!     },
//! };
//!
//! struct Transport([u8; 2]);
//!
//! struct Response<'a>(&'a [u8]);
//!
//! impl IpmiResponseView for Response<'_> {
//!     fn netfn(&self) -> NetFn { NetFn::App }
//!     fn cmd(&self) -> u8 { 0x42 }
//!     fn completion_code(&self) -> u8 { 0xc0 }
//!     fn data(&self) -> &[u8] { self.0 }
//! }
//!
//! impl IpmiExchange for Transport {
//!     type Target = ();
//!     type Error = ();
//!     type Response<'a> = Response<'a>;
//!
//!     fn exchange<'a>(&'a mut self, _: (), _: EncodedRequest<'_>) -> Result<Response<'a>, ()> {
//!         Ok(Response(&self.0))
//!     }
//! }
//!
//! let mut transport = Transport([0xaa, 0xbb]);
//! let mut buffer = [0; 1];
//! let command = GetChannelInfo::new(Channel::Current);
//! let request = command.encode_request(&mut buffer).unwrap();
//!
//! let response = transport.exchange((), request).unwrap();
//! assert_eq!(response.data(), &[0xaa, 0xbb]);
//! assert!(parse_response::<GetChannelInfo>(&request, &response).is_err());
//! ```

use core::fmt::Debug;

use super::{CompletionErrorCode, EncodeError, EncodedRequest, IpmiCommand, NetFn};

/// A response to an IPMI request, viewed without taking ownership of its bytes.
pub trait IpmiResponseView {
    /// The network function of the response.
    fn netfn(&self) -> NetFn;

    /// The command byte of the response.
    fn cmd(&self) -> u8;

    /// The raw completion code of the response; `0` means success.
    fn completion_code(&self) -> u8;

    /// The response data, not including the completion code.
    fn data(&self) -> &[u8];

    /// The completion code as an error, or `None` if it indicates success.
    fn completion_error(&self) -> Option<CompletionErrorCode> {
        CompletionErrorCode::try_from(self.completion_code()).ok()
    }
}

#[cfg(feature = "alloc")]
impl IpmiResponseView for super::Response {
    fn netfn(&self) -> NetFn {
        super::Response::netfn(self)
    }

    fn cmd(&self) -> u8 {
        super::Response::cmd(self)
    }

    fn completion_code(&self) -> u8 {
        self.cc()
    }

    fn data(&self) -> &[u8] {
        super::Response::data(self)
    }
}

/// Why a response could not be turned into a command's output.
///
/// The raw response data is not kept; the completion code and the command's own error are. A response may borrow
/// from the transport, so an error holding the data would keep the transport borrowed until the error was dropped.
/// [`IpmiCommand::handle_completion_code`] still receives the data and can put what it needs into the command's own
/// error. To read the data yourself, see the module docs.
#[derive(Debug, Clone, PartialEq)]
pub enum ResponseError<C> {
    /// The response answers a different request than the one that was sent.
    Unexpected {
        /// The network function that was sent.
        netfn_sent: NetFn,
        /// The network function that was received.
        netfn_recvd: NetFn,
        /// The command that was sent.
        cmd_sent: u8,
        /// The command that was received.
        cmd_recvd: u8,
    },
    /// The completion code reports a failure the command does not interpret.
    Failed {
        /// The reported completion code.
        completion_code: CompletionErrorCode,
    },
    /// The command reported an error: it interpreted a failed completion code, or it could not parse a successful
    /// response.
    Command {
        /// The command's error.
        error: C,
        /// The completion code, if the failure came from one.
        completion_code: Option<CompletionErrorCode>,
    },
}

/// Why an exchange did not produce a command's output.
#[derive(Debug, Clone, PartialEq)]
pub enum ExchangeError<T, C> {
    /// The request did not fit the provided buffer.
    Encode(EncodeError),
    /// The transport failed.
    Exchange(T),
    /// The transport returned a response the command rejected.
    Response(ResponseError<C>),
}

/// Checks that `response` answers `request`, then turns it into the output of command `C`.
///
/// # Errors
///
/// Returns [`ResponseError`] when the response answers another request, reports a failed completion code, or does
/// not parse.
pub fn parse_response<C: IpmiCommand>(
    request: &EncodedRequest<'_>,
    response: &impl IpmiResponseView,
) -> Result<C::Output, ResponseError<C::Error>> {
    // `request_value` maps a reserved response value onto the same request value, so both directions compare equal.
    if response.netfn().request_value() != request.netfn().request_value()
        || response.cmd() != request.cmd()
    {
        return Err(ResponseError::Unexpected {
            netfn_sent: request.netfn(),
            netfn_recvd: response.netfn(),
            cmd_sent: request.cmd(),
            cmd_recvd: response.cmd(),
        });
    }

    if let Some(completion_code) = response.completion_error() {
        return Err(
            match C::handle_completion_code(completion_code, response.data()) {
                Some(error) => ResponseError::Command {
                    error,
                    completion_code: Some(completion_code),
                },
                None => ResponseError::Failed { completion_code },
            },
        );
    }

    C::parse_success_response(response.data()).map_err(|error| ResponseError::Command {
        error,
        completion_code: None,
    })
}

/// A transport that exchanges one encoded request for one response.
///
/// The response may borrow from the transport, so it must be used before the next exchange. A transport that does
/// not keep the bytes can return an owned type from [`Self::Response`].
pub trait IpmiExchange {
    /// Where a request is addressed on this transport, e.g. a responder address and LUN.
    type Target;

    /// The transport's error.
    type Error: Debug;

    /// The response type, which may borrow from the transport.
    type Response<'a>: IpmiResponseView
    where
        Self: 'a;

    /// Sends `request` to `target` and waits for its response.
    ///
    /// # Errors
    ///
    /// Returns the transport's error if the exchange fails.
    fn exchange<'a>(
        &'a mut self,
        target: Self::Target,
        request: EncodedRequest<'_>,
    ) -> Result<Self::Response<'a>, Self::Error>;

    /// Encodes `command` into `buffer`, exchanges it with `target`, and parses the response.
    ///
    /// `target` says where to send the request, in the form this transport addresses destinations. The IPMI address
    /// and channel from [`IpmiCommand::target`] are not read, so map them to a `target` yourself if you need them. The
    /// raw data of a failed response is not kept; see the module docs.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] if `buffer` is too small, the transport fails, or the response is rejected.
    fn send_recv<C: IpmiCommand>(
        &mut self,
        target: Self::Target,
        command: &C,
        buffer: &mut [u8],
    ) -> Result<C::Output, ExchangeError<Self::Error, C::Error>> {
        let request = command
            .encode_request(buffer)
            .map_err(ExchangeError::Encode)?;
        let response = self
            .exchange(target, request)
            .map_err(ExchangeError::Exchange)?;
        parse_response::<C>(&request, &response).map_err(ExchangeError::Response)
    }
}

/// An async [`IpmiExchange`].
///
/// The futures are not required to be `Send`, so single-threaded executors such as Embassy can use it directly.
#[allow(async_fn_in_trait)]
pub trait AsyncIpmiExchange {
    /// Where a request is addressed on this transport, e.g. a responder address and LUN.
    type Target;

    /// The transport's error.
    type Error: Debug;

    /// The response type, which may borrow from the transport.
    type Response<'a>: IpmiResponseView
    where
        Self: 'a;

    /// Sends `request` to `target` and waits for its response.
    ///
    /// # Errors
    ///
    /// Returns the transport's error if the exchange fails.
    async fn exchange<'a>(
        &'a mut self,
        target: Self::Target,
        request: EncodedRequest<'_>,
    ) -> Result<Self::Response<'a>, Self::Error>;

    /// Encodes `command` into `buffer`, exchanges it with `target`, and parses the response.
    ///
    /// `target` says where to send the request, in the form this transport addresses destinations. The IPMI address
    /// and channel from [`IpmiCommand::target`] are not read, so map them to a `target` yourself if you need them. The
    /// raw data of a failed response is not kept; see the module docs.
    ///
    /// # Errors
    ///
    /// Returns [`ExchangeError`] if `buffer` is too small, the transport fails, or the response is rejected.
    async fn send_recv<C: IpmiCommand>(
        &mut self,
        target: Self::Target,
        command: &C,
        buffer: &mut [u8],
    ) -> Result<C::Output, ExchangeError<Self::Error, C::Error>> {
        let request = command
            .encode_request(buffer)
            .map_err(ExchangeError::Encode)?;
        let response = self
            .exchange(target, request)
            .await
            .map_err(ExchangeError::Exchange)?;
        parse_response::<C>(&request, &response).map_err(ExchangeError::Response)
    }
}

#[cfg(test)]
mod tests {
    use core::{
        future::Future,
        pin::pin,
        task::{Context, Poll, Waker},
    };

    use super::{AsyncIpmiExchange, ExchangeError, IpmiExchange, IpmiResponseView, ResponseError};
    use crate::connection::{
        CompletionErrorCode, EncodeError, EncodeIpmiCommand, EncodedRequest, IpmiCommand, NetFn,
    };

    /// Sends one byte and returns the first byte of the response.
    struct Echo(u8);

    impl EncodeIpmiCommand for Echo {
        const NETFN: NetFn = NetFn::App;
        const CMD: u8 = 0x01;

        fn request_data_len(&self) -> usize {
            1
        }

        fn write_request_data(&self, data: &mut [u8]) {
            data[0] = self.0;
        }
    }

    impl IpmiCommand for Echo {
        type Output = u8;
        type Error = &'static str;

        fn handle_completion_code(
            completion_code: CompletionErrorCode,
            _data: &[u8],
        ) -> Option<Self::Error> {
            matches!(completion_code, CompletionErrorCode::CommandSpecific(0x81))
                .then_some("command specific")
        }

        fn parse_success_response(data: &[u8]) -> Result<Self::Output, Self::Error> {
            data.first().copied().ok_or("empty response")
        }
    }

    /// A response that borrows its data from the transport.
    struct Borrowed<'a> {
        netfn: NetFn,
        cmd: u8,
        completion_code: u8,
        data: &'a [u8],
    }

    impl IpmiResponseView for Borrowed<'_> {
        fn netfn(&self) -> NetFn {
            self.netfn
        }

        fn cmd(&self) -> u8 {
            self.cmd
        }

        fn completion_code(&self) -> u8 {
            self.completion_code
        }

        fn data(&self) -> &[u8] {
            self.data
        }
    }

    /// Answers every request from a buffer it owns, so the response borrows from `&mut self`.
    struct Loopback {
        buffer: [u8; 4],
        netfn: NetFn,
        cmd: u8,
        completion_code: u8,
        len: usize,
        sent: Option<(NetFn, u8, u8, u8)>,
    }

    impl Loopback {
        fn answering(completion_code: u8, data: &[u8]) -> Self {
            let mut buffer = [0; 4];
            buffer[..data.len()].copy_from_slice(data);
            Self {
                buffer,
                netfn: NetFn::App,
                cmd: Echo::CMD,
                completion_code,
                len: data.len(),
                sent: None,
            }
        }

        fn respond(&mut self, target: u8, request: &EncodedRequest<'_>) -> Borrowed<'_> {
            self.sent = Some((request.netfn(), request.cmd(), request.data()[0], target));
            Borrowed {
                netfn: self.netfn,
                cmd: self.cmd,
                completion_code: self.completion_code,
                data: &self.buffer[..self.len],
            }
        }
    }

    impl IpmiExchange for Loopback {
        type Target = u8;
        type Error = &'static str;
        type Response<'a> = Borrowed<'a>;

        fn exchange<'a>(
            &'a mut self,
            target: u8,
            request: EncodedRequest<'_>,
        ) -> Result<Borrowed<'a>, Self::Error> {
            Ok(self.respond(target, &request))
        }
    }

    impl AsyncIpmiExchange for Loopback {
        type Target = u8;
        type Error = &'static str;
        type Response<'a> = Borrowed<'a>;

        async fn exchange<'a>(
            &'a mut self,
            target: u8,
            request: EncodedRequest<'_>,
        ) -> Result<Borrowed<'a>, Self::Error> {
            Ok(self.respond(target, &request))
        }
    }

    fn block_on<F: Future>(future: F) -> F::Output {
        let mut future = pin!(future);
        let mut context = Context::from_waker(Waker::noop());
        loop {
            if let Poll::Ready(output) = future.as_mut().poll(&mut context) {
                return output;
            }
        }
    }

    fn send_sync(loopback: &mut Loopback) -> Result<u8, ExchangeError<&'static str, &'static str>> {
        IpmiExchange::send_recv(loopback, 0x10, &Echo(0x7e), &mut [0; 1])
    }

    #[test]
    fn response_borrowed_from_the_transport_is_parsed() {
        let mut loopback = Loopback::answering(0x00, &[0x42]);

        assert_eq!(send_sync(&mut loopback), Ok(0x42));
        assert_eq!(loopback.sent, Some((NetFn::App, 0x01, 0x7e, 0x10)));
    }

    #[test]
    fn async_exchange_parses_the_same_way() {
        let mut loopback = Loopback::answering(0x00, &[0x42]);

        let output = block_on(AsyncIpmiExchange::send_recv(
            &mut loopback,
            0x10,
            &Echo(0x7e),
            &mut [0; 1],
        ));

        assert_eq!(output, Ok(0x42));
        assert_eq!(loopback.sent, Some((NetFn::App, 0x01, 0x7e, 0x10)));
    }

    #[test]
    fn small_buffer_fails_before_the_transport_is_used() {
        let mut loopback = Loopback::answering(0x00, &[0x42]);

        let output = IpmiExchange::send_recv(&mut loopback, 0x10, &Echo(0), &mut []);

        assert_eq!(
            output,
            Err(ExchangeError::Encode(EncodeError {
                required: 1,
                available: 0,
            }))
        );
        assert_eq!(loopback.sent, None);
    }

    #[test]
    fn response_to_another_command_is_rejected() {
        let mut loopback = Loopback::answering(0x00, &[0x42]);
        loopback.cmd = 0x02;

        assert_eq!(
            send_sync(&mut loopback),
            Err(ExchangeError::Response(ResponseError::Unexpected {
                netfn_sent: NetFn::App,
                netfn_recvd: NetFn::App,
                cmd_sent: 0x01,
                cmd_recvd: 0x02,
            }))
        );
    }

    #[test]
    fn response_netfn_matches_regardless_of_direction_bit() {
        let mut loopback = Loopback::answering(0x00, &[0x42]);
        loopback.netfn = NetFn::Reserved(0x2d);
        let request = EncodedRequest {
            netfn: NetFn::Reserved(0x2c),
            cmd: Echo::CMD,
            data: &[0],
        };

        let response = loopback.respond(0x10, &request);

        assert_eq!(super::parse_response::<Echo>(&request, &response), Ok(0x42));
    }

    #[test]
    fn failed_response_data_is_available_through_the_two_step_path() {
        let mut loopback = Loopback::answering(0xc0, &[0xaa, 0xbb]);
        let mut buffer = [0; 1];
        let request = Echo(0x7e).encode_request(&mut buffer).unwrap();

        let response = IpmiExchange::exchange(&mut loopback, 0x10, request).unwrap();

        assert_eq!(response.data(), &[0xaa, 0xbb]);
        assert_eq!(
            super::parse_response::<Echo>(&request, &response),
            Err(ResponseError::Failed {
                completion_code: CompletionErrorCode::NodeBusy,
            })
        );
    }

    #[test]
    fn failed_completion_code_without_command_handling_is_reported() {
        let mut loopback = Loopback::answering(0xc0, &[]);

        assert_eq!(
            send_sync(&mut loopback),
            Err(ExchangeError::Response(ResponseError::Failed {
                completion_code: CompletionErrorCode::NodeBusy,
            }))
        );
    }

    #[test]
    fn command_interprets_its_own_completion_code() {
        let mut loopback = Loopback::answering(0x81, &[]);

        assert_eq!(
            send_sync(&mut loopback),
            Err(ExchangeError::Response(ResponseError::Command {
                error: "command specific",
                completion_code: Some(CompletionErrorCode::CommandSpecific(0x81)),
            }))
        );
    }

    #[test]
    fn unparsable_success_response_is_a_command_error() {
        let mut loopback = Loopback::answering(0x00, &[]);

        assert_eq!(
            send_sync(&mut loopback),
            Err(ExchangeError::Response(ResponseError::Command {
                error: "empty response",
                completion_code: None,
            }))
        );
    }

    #[test]
    #[cfg(feature = "alloc")]
    fn owned_response_is_a_view() {
        use crate::connection::{Message, Response};

        let message = Message::new_response(NetFn::App, 0x01, alloc::vec![0x00, 0x42]);
        let response = Response::new(message, 0).unwrap();

        assert_eq!(IpmiResponseView::completion_code(&response), 0x00);
        assert_eq!(IpmiResponseView::data(&response), &[0x42]);
        assert_eq!(IpmiResponseView::netfn(&response), NetFn::App);
    }
}
