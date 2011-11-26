# -*- coding: utf-8 -*-
#
# simpatiCA - a simple PKI
#
# Copyright (C) 2011 by Michele Comitini <michele.comitini _at_ glisco.it>
# Copyright (C) 2011 by Glisco s.r.l. <info _at_ glisco.it>
#
#     This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# see LICENSE for licensing info.

#########################################################################
## Customize your APP title, subtitle and menus here
#########################################################################

response.title = "SimpatiCA"
response.subtitle = T('a simple PKI for Web2py')

## read more at http://dev.w3.org/html5/markup/meta.name.html
response.meta.author = 'Michele Comitini <mcm _at_ glisco.it>'
response.meta.description = 'a simple PKI for Web2py'
response.meta.keywords = 'pki, ca, web2py, python'
response.meta.generator = 'Web2py Web Framework'
response.meta.copyright = 'Copyright (C) 2011 Glisco S.R.L., www.glisco.it'

## your http://google.com/analytics id
response.google_analytics_id = None

#########################################################################
## this is the main application menu add/remove items as required
#########################################################################

response.menu = [
    (T('Public'), False, URL('public','index'), []),
    (T('CA'), False, URL('ca','index'), []),
    ]

