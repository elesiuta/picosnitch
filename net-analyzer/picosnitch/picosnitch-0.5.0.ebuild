# Copyright 2021 Gentoo Authors
# Distributed under the terms of the GNU General Public License v2

EAPI=7
PYTHON_COMPAT=( python3_{7,8,9} )
DISTUTILS_SINGLE_IMPL=1
inherit distutils-r1

DESCRIPTION="A small program for notifying you whenever a program makes its first network connection"
HOMEPAGE="https://github.com/elesiuta/picosnitch"
SRC_URI="mirror://pypi/${PN:0:1}/${PN}/${P}.tar.gz"

LICENSE="GPL-3"
SLOT="0"
KEYWORDS="~amd64"

DEPEND="dev-util/bcc
	dev-python/psutil"
RDEPEND="${DEPEND}"
DOCS=( README.md )
