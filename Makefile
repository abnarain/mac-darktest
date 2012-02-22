#
# Copyright (C) 2006-2011 OpenWrt.org
#
# This is free software, licensed under the GNU General Public License v2.
# See /LICENSE for more information.
#

include $(TOPDIR)/rules.mk

PKG_NAME:=sniffer
PKG_VERSION:=1.0
PKG_RELEASE:=1

# XXX - what are the depends?
#PKG_BUILD_DEPENDS:=libpcap

include $(INCLUDE_DIR)/package.mk

# DEPENDS:=+libpthread
define Package/sniffer
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

define Package/sniffer/install
	$(INSTALL_DIR) $(1)/usr/bin
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/sniffer $(1)/usr/bin/sniffer
endef

$(eval $(call BuildPackage,sniffer))
