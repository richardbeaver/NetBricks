use bencode::{encode, BValue};
use std::path::PathBuf;

#[derive(Clone)]
pub struct Torrent {
    pub tracker_url: String,
    pub info: TorrentInfo,
}

#[derive(Clone)]
pub struct TorrentInfo {
    pub root: PathBuf,
    pub piece_length: u64,
    pub pieces: Vec<[u8; 20]>,
    pub files: Vec<File>,
}

#[derive(Clone)]
pub struct File {
    pub path: PathBuf,
    pub length: u64,
}

#[derive(Debug, Eq, PartialEq)]
pub enum DecodeError {
    MissingTracker,
    MissingInfo,
    MissingName,
    MissingPieceLength,
    MissingPieces,
    MissingFiles,
    BadPieceLength,
    BadPieces,
    BadFile,
    BadFilePath,
    UTF8Error,
}

pub type DecodeResult<T> = Result<T, DecodeError>;

pub fn from_bvalue(value: BValue) -> DecodeResult<(Torrent, [u8; 20])> {
    let mut dict = value.get_dict().ok_or(DecodeError::MissingTracker)?;

    let tracker = dict
        .remove(&b"announce"[..])
        .and_then(BValue::get_string)
        .ok_or(DecodeError::MissingTracker)
        .and_then(decode_string)?;

    let (info, hash) = dict
        .remove(&b"info"[..])
        .ok_or(DecodeError::MissingInfo)
        .and_then(decode_info)?;

    Ok((
        Torrent {
            tracker_url: tracker,
            info: info,
        },
        hash,
    ))
}

fn hash_info(value: &BValue) -> [u8; 20] {
    let encoded = encode(value);
    let mut hasher = ::sha1::Sha1::new();
    hasher.update(&encoded);
    hasher.digest().bytes()
}

fn decode_info(value: BValue) -> DecodeResult<(TorrentInfo, [u8; 20])> {
    let hash = hash_info(&value);
    let mut dict = value.get_dict().ok_or(DecodeError::MissingName)?;

    let name = dict
        .remove(&b"name"[..])
        .and_then(BValue::get_string)
        .ok_or(DecodeError::MissingName)
        .and_then(decode_string)
        .map(PathBuf::from)?;

    let piece_length = dict
        .remove(&b"piece length"[..])
        .and_then(|x| x.get_int())
        .ok_or(DecodeError::MissingPieceLength)
        .and_then(|x| int_to_unsigned(x).ok_or(DecodeError::BadPieceLength))?;

    let pieces = dict
        .remove(&b"pieces"[..])
        .and_then(BValue::get_string)
        .ok_or(DecodeError::MissingPieces)
        .and_then(split_piece_hashes)?;

    let length = dict.remove(&b"length"[..]).and_then(|x| x.get_int());

    let files = match length {
        Some(len) => {
            let len = int_to_unsigned(len).ok_or(DecodeError::BadFile)?;
            let path = name.clone();
            vec![File {
                length: len,
                path: path,
            }]
        }
        None => {
            let files = dict
                .remove(&b"files"[..])
                .and_then(BValue::get_list)
                .ok_or(DecodeError::MissingFiles)?;

            let mut decoded_files = Vec::new();
            for file in files.into_iter() {
                decoded_files.push(decode_file(file)?);
            }
            decoded_files
        }
    };

    Ok((
        TorrentInfo {
            root: name,
            piece_length: piece_length,
            pieces: pieces,
            files: files,
        },
        hash,
    ))
}

fn decode_file(value: BValue) -> DecodeResult<File> {
    let mut dict = value.get_dict().ok_or(DecodeError::BadFile)?;

    let path = dict
        .remove(&b"path"[..])
        .and_then(BValue::get_list)
        .ok_or(DecodeError::BadFile)
        .and_then(decode_path)
        .map(PathBuf::from)?;

    let length = dict
        .remove(&b"length"[..])
        .and_then(|x| x.get_int())
        .and_then(int_to_unsigned)
        .ok_or(DecodeError::BadFile)?;

    Ok(File {
        path: path,
        length: length,
    })
}

fn decode_string(bytes: Vec<u8>) -> DecodeResult<String> {
    String::from_utf8(bytes).map_err(|_| DecodeError::UTF8Error)
}

fn decode_path(segments: Vec<BValue>) -> DecodeResult<PathBuf> {
    let mut path = PathBuf::new();
    for segment in segments.into_iter() {
        let segment = segment
            .get_string()
            .ok_or(DecodeError::BadFilePath)
            .and_then(|s| decode_string(s))
            .map_err(|_| DecodeError::BadFilePath)?;
        let segment = PathBuf::from(segment);
        path.push(segment);
    }
    Ok(path)
}

fn int_to_unsigned(i: i64) -> Option<u64> {
    if i >= 0 {
        Some(i as u64)
    } else {
        None
    }
}

fn split_piece_hashes(raw: Vec<u8>) -> DecodeResult<Vec<[u8; 20]>> {
    if raw.len() % 20 != 0 {
        Err(DecodeError::BadPieces)
    } else {
        let mut result = Vec::new();
        let pieces = raw.len() / 20;
        for i in 0..pieces {
            let slice = &raw[(i * 20)..(i * 20 + 20)];
            let mut array = [0_u8; 20];
            for j in 0..20 {
                array[j] = slice[j];
            }
            result.push(array);
        }
        Ok(result)
    }
}
