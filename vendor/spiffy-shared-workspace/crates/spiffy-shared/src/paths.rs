use std::path::PathBuf;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Product {
    Clipboard,
    Shelf,
    Search,
}

impl Product {
    pub const fn directory_name(self) -> &'static str {
        match self {
            Self::Clipboard => "SpiffyClipboard",
            Self::Shelf => "SpiffyShelf",
            Self::Search => "SpiffySearch",
        }
    }
}

pub fn product_data_dir(product: Product) -> PathBuf {
    platform_data_root().join(product.directory_name())
}

pub fn product_cache_dir(product: Product) -> PathBuf {
    platform_cache_root().join(product.directory_name())
}

pub fn product_log_dir(product: Product) -> PathBuf {
    product_data_dir(product).join("logs")
}

pub fn cross_shelf_data_dir() -> PathBuf {
    product_data_dir(Product::Shelf).join("cross-shelf")
}

pub fn cross_shelf_cache_dir() -> PathBuf {
    product_cache_dir(Product::Shelf)
        .join("cross-shelf")
        .join("cache")
}

pub fn cross_shelf_staging_dir() -> PathBuf {
    cross_shelf_data_dir().join("staging")
}

#[cfg(windows)]
fn platform_data_root() -> PathBuf {
    std::env::var_os("LOCALAPPDATA")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join("AppData").join("Local"))
}

#[cfg(target_os = "macos")]
fn platform_data_root() -> PathBuf {
    home_dir().join("Library").join("Application Support")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_data_root() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".local").join("share"))
}

#[cfg(windows)]
fn platform_cache_root() -> PathBuf {
    platform_data_root()
}

#[cfg(target_os = "macos")]
fn platform_cache_root() -> PathBuf {
    home_dir().join("Library").join("Caches")
}

#[cfg(all(unix, not(target_os = "macos")))]
fn platform_cache_root() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| home_dir().join(".cache"))
}

fn home_dir() -> PathBuf {
    std::env::var_os("USERPROFILE")
        .or_else(|| std::env::var_os("HOME"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn products_never_share_a_data_directory() {
        assert_ne!(
            product_data_dir(Product::Clipboard),
            product_data_dir(Product::Shelf)
        );
        assert_ne!(
            product_data_dir(Product::Clipboard),
            product_data_dir(Product::Search)
        );
        assert_ne!(
            product_data_dir(Product::Shelf),
            product_data_dir(Product::Search)
        );
    }

    #[test]
    fn cross_shelf_paths_stay_under_the_shelf_owner() {
        let shelf = product_data_dir(Product::Shelf);
        assert!(cross_shelf_data_dir().starts_with(&shelf));
        assert!(cross_shelf_staging_dir().starts_with(&shelf));
    }
}
