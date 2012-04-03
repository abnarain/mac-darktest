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


include $(INCLUDE_DIR)/package.mk

define Package/mac-darktest
	SECTION:=net
	CATEGORY:=Network
	TITLE:= collects wireless statistics from PHY to Network layer
	URL:=http://doesnotexist.com
	DEPENDS:=+zlib +libnl-tiny +bismark-data-transmit 
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
