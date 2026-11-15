use std::borrow::Cow;
use std::sync::RwLock;

pub const TAG_DIRECT: u8 = 0;
pub const TAG_PROXY: u8 = 1;
pub const TAG_USER: u8 = 2;
pub const TAG_MAX: u8 = 251;
pub const TAG_HOSTS: u8 = 252;
pub const TAG_ADBLOCK: u8 = 255;

static CUSTOM_TAGS: RwLock<Vec<String>> = RwLock::new(Vec::new());

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Tag {
    Direct,
    Proxy,
    Hosts,
    Adblock,
    Custom(u8),
}

impl Tag {
    #[inline]
    pub fn int(&self) -> u8 {
        match self {
            Tag::Direct => TAG_DIRECT,
            Tag::Proxy => TAG_PROXY,
            Tag::Hosts => TAG_HOSTS,
            Tag::Adblock => TAG_ADBLOCK,
            Tag::Custom(v) => *v,
        }
    }

    pub fn name(&self) -> Cow<'static, str> {
        match self {
            Tag::Direct => Cow::Borrowed("direct"),
            Tag::Proxy => Cow::Borrowed("proxy"),
            Tag::Hosts => Cow::Borrowed("hosts"),
            Tag::Adblock => Cow::Borrowed("adblock"),
            Tag::Custom(v) => {
                let tags = CUSTOM_TAGS.read().unwrap();
                let idx = (*v as usize).saturating_sub(TAG_USER as usize);
                if idx < tags.len() {
                    Cow::Owned(tags[idx].clone())
                } else {
                    Cow::Owned(format!("<user-{}>", v))
                }
            }
        }
    }

    #[inline]
    pub fn from_int(v: u8) -> Self {
        match v {
            TAG_DIRECT => Tag::Direct,
            TAG_PROXY => Tag::Proxy,
            TAG_HOSTS => Tag::Hosts,
            TAG_ADBLOCK => Tag::Adblock,
            custom @ TAG_USER..=TAG_MAX => Tag::Custom(custom),
            _ => Tag::Direct,
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "direct" | "polar" | "chn" => Some(Tag::Direct),
            "proxy" | "gfw" => Some(Tag::Proxy),
            "hosts" => Some(Tag::Hosts),
            "adblock" | "block" => Some(Tag::Adblock),
            _ => {
                let tags = CUSTOM_TAGS.read().unwrap();
                tags.iter()
                    .position(|t| t == name)
                    .map(|pos| Tag::Custom(pos as u8 + TAG_USER))
            }
        }
    }

    /// Register a user-defined tag.
    /// If already registered, the same tag value is returned.
    pub fn register(name: &str) -> Result<Self, bool> {
        if let Some(tag) = Self::from_name(name) {
            return Ok(tag);
        }

        let mut tags = CUSTOM_TAGS.write().unwrap();
        let new_id = match TAG_USER.checked_add(tags.len() as u8) {
            Some(id) if id <= TAG_MAX => id,
            _ => return Err(true), // Overflow check
        };

        tags.push(name.to_string());
        Ok(Tag::Custom(new_id))
    }
}

#[cfg(test)]
pub fn reset_custom_tags() {
    let mut tags = CUSTOM_TAGS.write().unwrap();
    tags.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_to_name() {
        assert_eq!(Tag::Direct.name(), "direct");
        assert_eq!(Tag::Proxy.name(), "proxy");
    }

    #[test]
    fn test_from_name() {
        assert_eq!(Tag::from_name("direct"), Some(Tag::Direct));
        assert_eq!(Tag::from_name("polar"), Some(Tag::Direct));
        assert_eq!(Tag::from_name("chn"), Some(Tag::Direct));
        assert_eq!(Tag::from_name("proxy"), Some(Tag::Proxy));
        assert_eq!(Tag::from_name("gfw"), Some(Tag::Proxy));
        assert_eq!(Tag::from_name("adblock"), Some(Tag::Adblock));
        assert_eq!(Tag::from_name("block"), Some(Tag::Adblock));
        assert_eq!(Tag::from_name("unknown"), None);
    }

    #[test]
    fn test_custom_tags() {
        let custom = Tag::register("custom1");
        assert!(custom.is_ok());
        let custom_tag = custom.unwrap();
        let val = custom_tag.int();
        assert!((TAG_USER..=TAG_MAX).contains(&val));
        assert_eq!(custom_tag.name(), "custom1");

        let found = Tag::from_name("custom1");
        assert_eq!(found, Some(custom_tag));
    }
}
