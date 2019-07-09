use winapi::um::fileapi::{GetDiskFreeSpaceA};
use winapi::shared::minwindef::{DWORD};

use crate::{errno_result, Result};

#[derive(Debug, Clone, Copy)]
pub struct VolumeInfo {
    pub block_size: u64,
    pub sector_size: u64,
    pub free_blocks: u64,
    pub total_blocks: u64
}

impl VolumeInfo {
    pub fn get(path: &str) -> Result<Self> {
        let mut sectors_per_cluster: DWORD = 0;
        let mut bytes_per_sector: DWORD = 0;
        let mut number_of_free_clusters: DWORD = 0;
        let mut total_number_of_clusters: DWORD = 0;

        let ret_val = unsafe {
            GetDiskFreeSpaceA(
                path.as_bytes().as_ptr() as *const i8,
                &mut sectors_per_cluster,
                &mut bytes_per_sector,
                &mut number_of_free_clusters,
                &mut total_number_of_clusters)
        };
        if ret_val as usize == 0 {
            return errno_result();
        }

        return Ok(VolumeInfo {
            block_size: (sectors_per_cluster * bytes_per_sector) as u64,
            sector_size: bytes_per_sector as u64,
            free_blocks: number_of_free_clusters as u64,
            total_blocks: total_number_of_clusters as u64
        })
    }
}
