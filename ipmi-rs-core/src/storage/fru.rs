//! FRU inventory commands in the Storage network function (`0Ah`).
//!
//! Reference: IPMI 2.0 Specification, Sections 34.1–34.3

use crate::connection::{EncodeIpmiCommand, IpmiCommand, NetFn};

/// Errors from parsing a successful FRU command response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FruResponseError {
    /// The response does not contain the required fields.
    NotEnoughData,
    /// The returned count or data length is inconsistent with the access mode.
    InvalidResponse,
    /// The response data exceeds the capacity selected for `ReadFruData`.
    BufferTooSmall,
}

/// Get FRU Inventory Area Info (Storage command `10h`).
///
/// Reference: IPMI 2.0 Specification, Section 34.1
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GetFruInventoryAreaInfo {
    /// FRU device ID; 0 selects the IPMC's own FRU, and `FFh` is reserved.
    pub fru_device_id: u8,
}

impl EncodeIpmiCommand for GetFruInventoryAreaInfo {
    const NETFN: NetFn = NetFn::Storage;
    const CMD: u8 = 0x10;

    fn request_data_len(&self) -> usize {
        1
    }

    fn write_request_data(&self, data: &mut [u8]) {
        data[0] = self.fru_device_id;
    }
}

/// FRU inventory addressing mode (response byte 4 bit 0).
///
/// Reference: IPMI 2.0 Specification, Table 34-2
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FruAccess {
    /// Offsets and counts are in bytes.
    ByBytes,
    /// Offsets and counts are in words (2 bytes per access unit).
    ByWords,
}

impl FruAccess {
    /// Number of bytes represented by one offset or count unit.
    pub const fn unit_bytes(self) -> usize {
        match self {
            Self::ByBytes => 1,
            Self::ByWords => 2,
        }
    }

    /// Convert a byte offset to access units, rejecting misalignment and offsets outside `u16`.
    pub fn encode_offset(self, byte_offset: usize) -> Option<u16> {
        let unit = self.unit_bytes();
        if byte_offset % unit != 0 {
            return None;
        }
        u16::try_from(byte_offset / unit).ok()
    }

    /// Convert a nonzero byte count to access units, rejecting misalignment and counts outside `u8`.
    pub fn encode_count(self, byte_count: usize) -> Option<u8> {
        let unit = self.unit_bytes();
        if byte_count == 0 || byte_count % unit != 0 {
            return None;
        }
        u8::try_from(byte_count / unit).ok()
    }

    /// Convert a command count from access units to bytes.
    pub const fn decode_count(self, count: u8) -> usize {
        count as usize * self.unit_bytes()
    }
}

/// Parsed Get FRU Inventory Area Info response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FruInventoryAreaInfo {
    /// Inventory size in bytes, regardless of the reported access mode.
    pub size_bytes: u16,
    /// Access mode for Read/Write FRU Data offsets and counts.
    pub access: FruAccess,
}

impl IpmiCommand for GetFruInventoryAreaInfo {
    type Output = FruInventoryAreaInfo;
    type Error = FruResponseError;

    fn parse_success_response(body: &[u8]) -> Result<Self::Output, Self::Error> {
        let [lsb, msb, access, ..] = *body else {
            return Err(FruResponseError::NotEnoughData);
        };
        Ok(FruInventoryAreaInfo {
            size_bytes: u16::from_le_bytes([lsb, msb]),
            access: if access & 0x01 == 0 {
                FruAccess::ByBytes
            } else {
                FruAccess::ByWords
            },
        })
    }
}

/// Read FRU Data (Storage command `11h`).
///
/// Reference: IPMI 2.0 Specification, Section 34.2
///
/// `CAPACITY` is the maximum number of returned data bytes the caller can store,
/// excluding the response's count byte. Select it for the transport in use;
/// a response larger than `CAPACITY` returns [`FruResponseError::BufferTooSmall`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReadFruData<const CAPACITY: usize> {
    /// FRU device ID; `FFh` is reserved.
    pub fru_device_id: u8,
    /// Logical offset in the device's reported access units.
    pub offset: u16,
    /// Nonzero access units to read; the responder may return fewer.
    pub count: u8,
}

impl<const CAPACITY: usize> ReadFruData<CAPACITY> {
    /// Create a read request with a nonzero count of the device's access units.
    pub fn new(fru_device_id: u8, offset: u16, count: u8) -> Option<Self> {
        (count != 0).then_some(Self {
            fru_device_id,
            offset,
            count,
        })
    }
}

impl<const CAPACITY: usize> EncodeIpmiCommand for ReadFruData<CAPACITY> {
    const NETFN: NetFn = NetFn::Storage;
    const CMD: u8 = 0x11;

    fn request_data_len(&self) -> usize {
        4
    }

    fn write_request_data(&self, data: &mut [u8]) {
        let offset = self.offset.to_le_bytes();
        data.copy_from_slice(&[self.fru_device_id, offset[0], offset[1], self.count]);
    }
}

/// Read FRU Data response: a count in access units followed by returned data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FruDataRead<const CAPACITY: usize> {
    count: u8,
    data: [u8; CAPACITY],
    data_len: usize,
}

impl<const CAPACITY: usize> FruDataRead<CAPACITY> {
    /// Return the data if its byte length equals the returned count in `access` units.
    pub fn bytes(&self, access: FruAccess) -> Result<&[u8], FruResponseError> {
        if self.data_len != access.decode_count(self.count) {
            return Err(FruResponseError::InvalidResponse);
        }
        Ok(&self.data[..self.data_len])
    }
}

impl<const CAPACITY: usize> IpmiCommand for ReadFruData<CAPACITY> {
    type Output = FruDataRead<CAPACITY>;
    type Error = FruResponseError;

    fn parse_success_response(body: &[u8]) -> Result<Self::Output, Self::Error> {
        let Some((&count, data)) = body.split_first() else {
            return Err(FruResponseError::NotEnoughData);
        };
        if count == 0 {
            return Err(FruResponseError::InvalidResponse);
        }
        if data.len() > CAPACITY {
            return Err(FruResponseError::BufferTooSmall);
        }
        let mut result = FruDataRead {
            count,
            data: [0; CAPACITY],
            data_len: data.len(),
        };
        result.data[..data.len()].copy_from_slice(data);
        Ok(result)
    }
}

/// Write FRU Data (Storage command `12h`).
///
/// Reference: IPMI 2.0 Specification, Section 34.3
///
/// The requested byte count comes from the length of `data`; the access unit
/// is reported by Get FRU Inventory Area Info.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WriteFruData<'a> {
    /// FRU device ID; `FFh` is reserved.
    pub fru_device_id: u8,
    /// Logical offset in the device's reported access units.
    pub offset: u16,
    data: &'a [u8],
}

impl<'a> WriteFruData<'a> {
    /// Create a write with a nonzero count of whole access units fitting the command's `u8` count.
    ///
    /// Transport-specific frame limits must be checked by the caller or transport.
    pub fn new(fru_device_id: u8, offset: u16, access: FruAccess, data: &'a [u8]) -> Option<Self> {
        access.encode_count(data.len())?;
        Some(Self {
            fru_device_id,
            offset,
            data,
        })
    }
}

impl EncodeIpmiCommand for WriteFruData<'_> {
    const NETFN: NetFn = NetFn::Storage;
    const CMD: u8 = 0x12;

    fn request_data_len(&self) -> usize {
        3 + self.data.len()
    }

    fn write_request_data(&self, data: &mut [u8]) {
        data[0] = self.fru_device_id;
        data[1..3].copy_from_slice(&self.offset.to_le_bytes());
        data[3..].copy_from_slice(self.data);
    }
}

/// Write FRU Data response: the count of access units written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FruDataWritten {
    /// Convert this count to bytes with [`FruAccess::decode_count`] before comparing it to the request.
    pub count: u8,
}

impl IpmiCommand for WriteFruData<'_> {
    type Output = FruDataWritten;
    type Error = FruResponseError;

    fn parse_success_response(body: &[u8]) -> Result<Self::Output, Self::Error> {
        match body.first().copied() {
            Some(0) => Err(FruResponseError::InvalidResponse),
            Some(count) => Ok(FruDataWritten { count }),
            None => Err(FruResponseError::NotEnoughData),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{FruAccess, FruResponseError, GetFruInventoryAreaInfo, ReadFruData, WriteFruData};
    use crate::connection::{EncodeIpmiCommand, IpmiCommand, NetFn};

    #[test]
    fn inventory_info_request_and_byte_size() {
        let command = GetFruInventoryAreaInfo { fru_device_id: 1 };
        let mut buffer = [0; 1];
        let request = command.encode_request(&mut buffer).unwrap();
        assert_eq!(request.netfn(), NetFn::Storage);
        assert_eq!(request.cmd(), 0x10);
        assert_eq!(request.data(), &[1]);

        let info = GetFruInventoryAreaInfo::parse_success_response(&[0x10, 0x02, 1]).unwrap();
        assert_eq!(info.size_bytes, 0x0210);
        assert_eq!(info.access, FruAccess::ByWords);
        assert_eq!(
            GetFruInventoryAreaInfo::parse_success_response(&[0, 0]),
            Err(FruResponseError::NotEnoughData)
        );
        assert_eq!(
            GetFruInventoryAreaInfo::parse_success_response(&[3, 0, 0])
                .unwrap()
                .access,
            FruAccess::ByBytes
        );
    }

    #[test]
    fn access_units_validate_alignment_and_field_widths() {
        assert_eq!(FruAccess::ByWords.encode_offset(8), Some(4));
        assert_eq!(FruAccess::ByWords.encode_offset(9), None);
        assert_eq!(
            FruAccess::ByWords.encode_offset(2 * usize::from(u16::MAX)),
            Some(u16::MAX)
        );
        assert_eq!(
            FruAccess::ByWords.encode_offset(2 * (usize::from(u16::MAX) + 1)),
            None
        );
        assert_eq!(FruAccess::ByWords.encode_count(0), None);
        assert_eq!(FruAccess::ByWords.encode_count(5), None);
        assert_eq!(FruAccess::ByWords.encode_count(510), Some(u8::MAX));
        assert_eq!(FruAccess::ByWords.encode_count(512), None);
        assert_eq!(FruAccess::ByBytes.encode_count(256), None);
        assert_eq!(FruAccess::ByWords.decode_count(3), 6);
    }

    #[test]
    fn read_request_encodes_offset_and_count() {
        assert!(ReadFruData::<4>::new(0, 0, 0).is_none());
        let command = ReadFruData::<4>::new(2, 0x0108, 2).unwrap();
        let mut buffer = [0; 4];
        let request = command.encode_request(&mut buffer).unwrap();
        assert_eq!(request.netfn(), NetFn::Storage);
        assert_eq!(request.cmd(), 0x11);
        assert_eq!(request.data(), &[2, 0x08, 0x01, 2]);
    }

    #[test]
    fn read_response_validates_access_units_and_capacity() {
        type Read = ReadFruData<4>;
        let response = Read::parse_success_response(&[2, 0xaa, 0xbb, 0xcc, 0xdd]).unwrap();
        assert_eq!(
            response.bytes(FruAccess::ByWords),
            Ok(&[0xaa, 0xbb, 0xcc, 0xdd][..])
        );
        assert_eq!(
            response.bytes(FruAccess::ByBytes),
            Err(FruResponseError::InvalidResponse)
        );
        assert_eq!(
            Read::parse_success_response(&[]),
            Err(FruResponseError::NotEnoughData)
        );
        assert_eq!(
            Read::parse_success_response(&[0]),
            Err(FruResponseError::InvalidResponse)
        );
        assert_eq!(
            Read::parse_success_response(&[1, 1, 2, 3, 4, 5]),
            Err(FruResponseError::BufferTooSmall)
        );
        let partial = Read::parse_success_response(&[2, 0xaa]).unwrap();
        assert_eq!(
            partial.bytes(FruAccess::ByBytes),
            Err(FruResponseError::InvalidResponse)
        );
    }

    #[test]
    fn write_request_validates_standard_count_not_transport_size() {
        assert!(WriteFruData::new(0, 0, FruAccess::ByBytes, &[]).is_none());
        assert!(WriteFruData::new(0, 0, FruAccess::ByWords, &[1]).is_none());
        let data = [0x55; 256];
        assert!(WriteFruData::new(0, 0, FruAccess::ByBytes, &data).is_none());
        assert!(WriteFruData::new(0, 0, FruAccess::ByWords, &data).is_some());
        assert!(WriteFruData::new(0, 0, FruAccess::ByWords, &[0; 512]).is_none());

        let command = WriteFruData::new(3, 0x0123, FruAccess::ByBytes, &[1, 2]).unwrap();
        let mut buffer = [0; 5];
        let request = command.encode_request(&mut buffer).unwrap();
        assert_eq!(request.netfn(), NetFn::Storage);
        assert_eq!(request.cmd(), 0x12);
        assert_eq!(request.data(), &[3, 0x23, 0x01, 1, 2]);
    }

    #[test]
    fn write_response_reports_access_unit_count() {
        type Write = WriteFruData<'static>;
        assert_eq!(
            Write::parse_success_response(&[]),
            Err(FruResponseError::NotEnoughData)
        );
        assert_eq!(
            Write::parse_success_response(&[0]),
            Err(FruResponseError::InvalidResponse)
        );
        assert_eq!(Write::parse_success_response(&[2]).unwrap().count, 2);
        assert_eq!(FruAccess::ByWords.decode_count(2), 4);
    }
}
