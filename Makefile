#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=mac-darktest
PKG_VERSION:=1.0
PKG_RELEASE:=1

# XXX - what are the depends?
#PKG_BUILD_DEPENDS:=libpcap

include $(INCLUDE_DIR)/package.mk

# DEPENDS:=+libpthread
define Package/mac-darktest
	SECTION:=net
	CATEGORY:=Network
	TITLE:=sniffes packets on wireless interface
	URL:=http://doesnotexist.com
	DEPENDS:=+libpcap 
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./src/* $(PKG_BUILD_DIR)
endef

define Package/mac-darktest/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/mac-darktest $(1)/usr/bin/mac-darktest
endef

$(eval $(call BuildPackage,mac-darktest))
