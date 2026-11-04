# WIM reader source

This directory contains modified DiscUtils WIM reader source from
https://github.com/LTRData/DiscUtils/tree/745ca1993227864ceaf3095eda1efd1c761e56be/Library/DiscUtils.Wim
(MIT; see `../licenses/DISCUTILS-LICENSE.txt`).

Solid-resource support (`SolidResource.cs`, and the solid grouping it performs
for `WimFile`) was rewritten clean-room on 2026-11-01. The earlier version drew
on 7-Zip's LGPL `WimIn.cpp`. The new one was written by an author who never saw
that code or 7-Zip's, working only from `SOLID-RESOURCE-SPEC.md`: format facts,
interface and safety rules, with no code from the earlier implementation. The
derived files were deleted before the new author began. No 7-Zip-derived code
remains in this directory. The program calls the Windows Compression API for raw
LZMS decoding.

With that, the program returned to the MIT licence (see
`../licenses/WIMDRIVE-MIT.txt`). It was offered under LGPL-2.1-or-later only
while the 7-Zip-derived code was on the read path.

Keep the MIT notices for this program and for DiscUtils with any compiled
application containing this reader.
