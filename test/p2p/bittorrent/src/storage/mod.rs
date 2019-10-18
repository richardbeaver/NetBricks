pub mod memory;
pub mod partial;

use downloader::request::Request;
use torrent::TorrentInfo;

pub struct BadBlock;

pub struct Block {
    pub piece: usize,
    pub offset: usize,
    pub data: Vec<u8>,
}

impl Block {
    pub fn new(piece: usize, offset: usize, data: Vec<u8>) -> Block {
        Block {
            piece: piece,
            offset: offset,
            data: data,
        }
    }
}

pub trait Storage {
    fn new(info: TorrentInfo) -> Self;
    fn get_piece(&mut self, index: usize) -> Option<&[u8]>;
    fn store_block(&mut self, block: Block) -> Result<usize, BadBlock>;
    fn bytes_missing(&self) -> usize;
    fn requests<'a>(&'a self) -> Box<dyn Iterator<Item = Request> + 'a>;

    fn is_complete(&self) -> bool {
        self.bytes_missing() == 0
    }

    fn has_piece(&mut self, index: usize) -> bool {
        self.get_piece(index).is_some()
    }
}
