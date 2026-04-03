use std::{
    fs,
    hash::{Hash, Hasher},
    io,
    path::Path,
};

use libafl::inputs::{HasTargetBytes, Input};
use libafl_bolts::{HasLen, ownedref::OwnedSlice};
use serde::{Deserialize, Deserializer, Serialize, Serializer, de};
use wl_repeater::{
    ir::{IrFileHeader, IrReader, decode_wlir, encode_wlir},
    message::WaylandMessage,
};

/// Primary LibAFL input model: parsed WLIR header + message vector in memory.
/// `.wlir` bytes remain a persistence/interop format via `to_wlir_bytes`.
#[derive(Debug, Clone)]
pub struct WlirInput {
    pub header: IrFileHeader,
    pub messages: Vec<WaylandMessage>,
}

impl WlirInput {
    #[allow(dead_code)]
    pub fn from_reader(mut reader: IrReader) -> io::Result<Self> {
        let header = reader.header;
        let messages = reader.read_all()?;
        Ok(Self { header, messages })
    }

    pub fn from_bytes(bytes: &[u8]) -> io::Result<Self> {
        let (header, messages) = decode_wlir(bytes)?;
        Ok(Self { header, messages })
    }

    pub fn to_wlir_bytes(&self) -> Vec<u8> {
        encode_wlir(&self.header, &self.messages)
    }
}

impl Hash for WlirInput {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.header.start_time_us.hash(state);
        self.to_wlir_bytes().hash(state);
    }
}

impl Serialize for WlirInput {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.to_wlir_bytes().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for WlirInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let bytes = Vec::<u8>::deserialize(deserializer)?;
        WlirInput::from_bytes(&bytes).map_err(de::Error::custom)
    }
}

impl Input for WlirInput {
    fn to_file<P>(&self, path: P) -> Result<(), libafl::Error>
    where
        P: AsRef<Path>,
    {
        fs::write(path, self.to_wlir_bytes()).map_err(Into::into)
    }

    fn from_file<P>(path: P) -> Result<Self, libafl::Error>
    where
        P: AsRef<Path>,
    {
        let bytes = fs::read(path)?;

        match WlirInput::from_bytes(&bytes) {
            Ok(parsed) => Ok(parsed),
            Err(_) => {
                let legacy: WlirInput = postcard::from_bytes(&bytes)?;
                Ok(legacy)
            }
        }
    }

    fn generate_name(&self, _id: Option<libafl::corpus::CorpusId>) -> String {
        format!("{:016x}.wlir", libafl_bolts::generic_hash_std(self))
    }
}

impl HasLen for WlirInput {
    fn len(&self) -> usize {
        self.messages.len()
    }
}

impl HasTargetBytes for WlirInput {
    fn target_bytes(&self) -> OwnedSlice<'_, u8> {
        OwnedSlice::from(self.to_wlir_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use tempfile::tempdir;
    use wl_repeater::{
        ir::{IrFileHeader, decode_wlir, encode_wlir},
        message::{Direction, FdRecord, FdType, FdUpdateRecord},
    };

    fn sample_header() -> IrFileHeader {
        IrFileHeader {
            magic: 0x574C_4952,
            version: 2,
            start_time_us: 123,
            flags: 1,
            reserved: 0,
        }
    }

    fn sample_message() -> WaylandMessage {
        WaylandMessage {
            timestamp_us: 456,
            instance_id: 9,
            object_id: 7,
            opcode: 3,
            direction: Direction::ClientToServer,
            wire_data: vec![7, 0, 0, 0, 3, 0, 16, 0, 1, 2, 3, 4, 5, 6, 7, 8],
            fds: vec![FdRecord {
                fd_num: 11,
                fd_type: FdType::Shm,
                seekable: true,
                truncated: false,
                format_hint: 22,
                original_size: 2,
                content: vec![0xAA, 0xBB],
            }],
            fd_updates: vec![FdUpdateRecord {
                object_id: 11,
                new_size: 128,
                content: vec![0x01, 0x02, 0x03],
            }],
            decoded_args: Vec::new(),
        }
    }

    #[test]
    fn len_returns_message_count() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message(), sample_message()],
        };

        assert_eq!(input.len(), 2);
    }

    #[test]
    fn target_bytes_start_with_wlir_magic() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };

        let bytes = input.to_wlir_bytes();
        assert_eq!(&bytes[0..4], &0x574C_4952u32.to_le_bytes());
    }

    #[test]
    fn to_wlir_bytes_matches_shared_encoder() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };

        assert_eq!(
            input.to_wlir_bytes(),
            encode_wlir(&input.header, &input.messages)
        );
    }

    #[test]
    fn from_bytes_matches_shared_decoder() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };
        let bytes = encode_wlir(&input.header, &input.messages);
        let (decoded_header, decoded_messages) = decode_wlir(&bytes).expect("bytes should decode");

        let parsed = WlirInput::from_bytes(&bytes).expect("bytes should parse");

        assert_eq!(parsed.header.magic, decoded_header.magic);
        assert_eq!(parsed.header.version, decoded_header.version);
        assert_eq!(parsed.header.start_time_us, decoded_header.start_time_us);
        assert_eq!(parsed.header.flags, decoded_header.flags);
        assert_eq!(parsed.header.reserved, decoded_header.reserved);
        assert_eq!(parsed.messages.len(), decoded_messages.len());
        assert_eq!(
            parsed.to_wlir_bytes(),
            encode_wlir(&decoded_header, &decoded_messages)
        );
    }

    #[test]
    fn round_trip_bytes_preserve_records() {
        let original = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };

        let bytes = original.to_wlir_bytes();
        let reparsed = WlirInput::from_bytes(&bytes).expect("bytes should parse");
        let reserialized = reparsed.to_wlir_bytes();

        assert_eq!(original.header.magic, reparsed.header.magic);
        assert_eq!(original.header.version, reparsed.header.version);
        assert_eq!(original.header.start_time_us, reparsed.header.start_time_us);
        assert_eq!(original.messages.len(), reparsed.messages.len());
        assert_eq!(bytes, reserialized);

        let msg = &reparsed.messages[0];
        assert_eq!(msg.fds.len(), 1);
        assert_eq!(msg.fds[0].fd_num, 11);
        assert_eq!(msg.fds[0].format_hint, 22);
        assert_eq!(msg.fds[0].content, vec![0xAA, 0xBB]);
        assert_eq!(msg.fd_updates.len(), 1);
        assert_eq!(msg.fd_updates[0].object_id, 11);
        assert_eq!(msg.fd_updates[0].new_size, 128);
        assert_eq!(msg.fd_updates[0].content, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn input_to_file_writes_raw_wlir_bytes() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("sample.wlir");

        input.to_file(&path).expect("to_file should write raw wlir");

        let mut bytes = Vec::new();
        std::fs::File::open(&path)
            .expect("written file should exist")
            .read_to_end(&mut bytes)
            .expect("should read written bytes");
        assert_eq!(bytes, input.to_wlir_bytes());
        assert_eq!(&bytes[0..4], &0x574C_4952u32.to_le_bytes());
    }

    #[test]
    fn input_from_file_accepts_legacy_postcard_encoded_files() {
        let input = WlirInput {
            header: sample_header(),
            messages: vec![sample_message()],
        };
        let dir = tempdir().unwrap();
        let path = dir.path().join("legacy");

        let legacy = postcard::to_allocvec(&input).expect("serialize legacy postcard");
        std::fs::write(&path, legacy).expect("write legacy file");

        let loaded = WlirInput::from_file(&path).expect("from_file should support legacy postcard");
        assert_eq!(loaded.to_wlir_bytes(), input.to_wlir_bytes());
    }
}
