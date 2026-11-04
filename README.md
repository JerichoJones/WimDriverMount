# WIM Driver Mount

Version 0.8.0 · Jericho Jones · MIT (third-party notices in `licenses`).

WIM Driver Mount mounts a WIM image as a read-only drive, without extracting it, from a
local disk, a network share, or an HTTP/HTTPS server. It can also run a program straight
from a WIM, and install the right drivers from a driver WIM.

**Drivers without staging.** Point it at a driver WIM on a share and let Plug and Play
work against it: nothing is extracted, nothing is copied to the machine first, and no
local disk space is needed for the driver set. A 20 GB driver WIM stays where it is;
Windows reads only the INFs that match the hardware in front of it, and copies into its
own driver store only the packages it actually installs. That makes it useful after a
machine is already running: the model's drivers changed, a device came back unknown, or a
technician wants the whole driver library available for one run and then gone.

The program is `WimDriverMount.exe`. It is self-contained: copy the folder anywhere, no
.NET installation needed. Run it with no arguments, or with `--help`, for a short guide.
It runs as administrator, so on a shared PC keep it in a folder only administrators can
write (under Program Files, say); it warns when its folder is not. `--install` puts it
there for you and adds a right-click Mount to File Explorer.

## Which one do I want?

| You want to… | Use | Section |
|---|---|---|
| Fix a PC's drivers from a driver WIM, in one go | drop the WIM on the program | [Install drivers](#install-drivers-from-a-wim) |
| See what it would install first | `--preview-drivers` | [Install drivers](#install-drivers-from-a-wim) |
| Keep this PC's drivers in a WIM | `--capture-drivers` | [Capture drivers](#capture-this-pcs-drivers-into-a-wim) |
| Browse or copy files from a WIM | `--wim … --drive M:` | [Mount a WIM as a drive](#mount-a-wim-as-a-drive) |
| Keep a drive mounted after the window closes | add `--background` | [Mount a WIM as a drive](#mount-a-wim-as-a-drive) |
| Mount a WIM from File Explorer, like an ISO | `--install` once, then right-click → Mount | [Install](#install-with-a-right-click-mount) |
| Let other accounts on this PC open the drive | add `--all-users` | [Mount a WIM as a drive](#mount-a-wim-as-a-drive) |
| Run an installer or tool that lives in a WIM | `--run` | [Run a program](#run-a-program-from-a-wim) |
| Do the same mounts on many machines | a settings file, `--mount-config` | [Settings file](#run-the-same-mounts-every-time) |
| Clean up after something went wrong | `--unmount`, `--resume-worker-cleanup` | [If something went wrong](#if-something-went-wrong) |

## Install drivers from a WIM

The quickest way: drop a driver WIM onto `WimDriverMount.exe`, or run, from the
program's folder:

```
.\WimDriverMount.exe C:\Drivers\Lenovo.wim
```

This and every example below works as written in both PowerShell and Command Prompt, once
you replace anything in `<...>` with your own value. Lines marked PowerShell are PowerShell only.

It mounts the WIM, reads every INF in it once, and for each device present picks the
driver Windows would rank best — by the driver's feature score, then how closely the
hardware ID matches, then date and version, the order Windows uses. It installs that
driver only where it beats the one already installed, then unmounts. Nothing restarts
automatically.

Windows also ranks by signer, but who signed a package is only known once Windows checks
its catalog, so every package is ranked as if signed by Microsoft (as almost every
driver package is). The installed driver's signer is likewise left out of the
comparison, so a driver signed below Microsoft's level is replaced only by a better
match or, at the same match, a newer one; Windows alone would also prefer an older
Microsoft-signed match. Windows checks every signature and does the installation
itself. If it refuses a package (a broken or tampered catalog, say) before touching the
device, that package is not tried again for any device and the next-ranked one is
used, as Windows' own installer would; the report shows the refusal. Only Windows'
verdict on the package counts: if the package could not be read (a share that stopped
answering, say), that is a failure and nothing else is tried. A device whose chosen
package Windows refused, and that no other package replaced, fails the run -- even if it
keeps a working driver. If Windows will not apply an extension,
the next-ranked extension of the same kind is handed over, and the run still fails.

**Preview first.** On a machine you care about, look before you install:

```
.\WimDriverMount.exe --wim C:\Drivers\Lenovo.wim --preview-drivers
```

This lists each device the WIM has a driver for, with the decision — INSTALL, KEEP,
SKIP, or EXTEND for an extension driver Windows would add — and the reason. It only reads the WIM: no mount, no Dokan, no administrator
prompt, no changes. When the list looks right, run the same command with
`--install-drivers` instead (or drop the WIM on the program).

**After installing** you get a driver report: each device where a driver was installed,
refused, failed or could not be decided, with totals. With `--log`, the log also gets a table of every device —
before, after, and the decision. If Windows reports that a restart is needed, the exit code is 3010.

Tips:

- One driver WIM can hold drivers for many models. Only drivers that match the hardware
  in front of it are considered, so a broad library is fine.
- Extension INFs (add-on packages some vendors ship beside the main driver) are chosen and
  installed the way Windows does it. One that cannot be read is skipped and named in the
  output; it never blocks the main driver.
- An INF that cannot be read blocks only the devices whose IDs it mentions, and the
  output names it. The rest of the WIM is still used.
- `--setup-log` marks the start and end of the run in Windows' own device-install log
  (`C:\Windows\INF\setupapi.dev.log`), so you can find this run there.
- Driver installs cannot run in the background; leave out `--background`.

How closely it matches Windows: compared with Windows' own results on one PC and one driver
set, INF parsing was identical on 949 INFs, candidate lists on 260 of 260 devices, and the
chosen driver on 127 of 127 devices (and 2 of 2 extensions). That is not a guarantee for
every machine.

## Capture this PC's drivers into a WIM

To keep this PC's drivers, for a reinstall or for another PC of the same model:

```
.\WimDriverMount.exe --capture-drivers C:\Drivers\this-pc.wim --whatif
.\WimDriverMount.exe --capture-drivers C:\Drivers\this-pc.wim
```

The first command lists what it would take and what it would leave out, and checks the
free space; it writes nothing. The second writes a new WIM with Windows' own WIM library
(`wimgapi.dll`). It needs administrator rights.

**What it takes:** the third-party driver packages (the `oemNN.inf` ones in Windows' driver
store) that this PC's hardware uses:

- the driver and extension packages of every hardware device, connected now or not (a
  dock or a printer that is unplugged today still counts);
- printers and scanners, and the drivers of print queues (a printer added by its network
  address has no device);
- the packages those install themselves (an INF's `CopyINF`, as AMD's display driver does).

Drivers that come with Windows are not taken: Windows already has them.

**What it leaves out, and says so:** each run lists every package something on this PC uses
that it leaves out, with the reason.

- *App-made devices:* a device that hangs from no hardware in Windows' device tree, such as
  a virtual sound card, game-pad bus or VPN adapter an app created. Windows has no flag for
  this; it is read from the device tree, so the list is worth a look.
- *Service-only drivers:* a package only a service uses (a VPN, a filter driver), with no
  device. `--install-drivers` installs a driver only where a device matches it, so such a
  package would only ever be a backup.

Third-party packages that nothing on this PC uses (older versions, drivers added but never
used, drivers of devices removed from the PC) are not captured either; the run says how many
and their size. If a captured INF
pulls in (`Include=`) another third-party INF from this PC's driver store that is not
captured, a WARNING names it.

**Compression:** `--compression none`, `fast` or `maximum` (the default). Each of the three
is tested end to end: captured, read back, mounted, and installed from. ESD files (LZMS
compression) are not written.

**Safety:**

- It only creates a new `.wim`; it refuses a name that exists.
- The WIM is written and checked in a folder only administrators can open, then copied to
  the folder you named.
- Before it reports success, every file is read back through this program's own WIM reader
  and compared with the driver store.
- It checks the free space first. The Windows drive needs the drivers' full size plus
  256 MB of working space; the target folder's drive needs the drivers' size. Both keep
  5 GB free on top.
- Ctrl+C stops it and leaves nothing behind. A capture that was killed leaves its working
  folder, which the next capture removes after 12 hours.

At the end it prints the WIM's SHA-256 and the command that installs from it on another PC,
refusing the file if it has changed since:

```
.\WimDriverMount.exe --wim 'C:\Drivers\this-pc.wim' --wim-sha256 <hash> --install-drivers
```

How it was checked: in a test VM, the packages it captured were identical, file for file,
to what Microsoft's `Export-WindowsDriver` exports for them (that exports every third-party
package, used or not), and a captured driver was removed and installed again from the WIM.
On an ARM64 test VM it captured, read back and mounted cleanly; reinstalling there is not yet
tested. On a real PC only the `--whatif` listing has been run.

## Mount a WIM as a drive

```
.\WimDriverMount.exe --wim C:\Images\tools.wim --drive M:
```

M: stays mounted until you press Ctrl+C in that window. Use this when you want to look
around in a WIM or copy a few files out of it.

```
.\WimDriverMount.exe --wim \\server\share\tools.wim --drive M: --background
.\WimDriverMount.exe --unmount M:
```

`--background` mounts the drive and returns; it stays mounted after the window closes,
until `--unmount`. Use this when other programs or later steps need the drive. While it
is mounted, right-clicking the drive in File Explorer also offers **Unmount with WIM
Driver Mount**, which runs the same `--unmount` (Windows 11 lists it under *Show more
options*). The entry is on that drive only and is removed when it unmounts. From the
installed program it is there for every account, as the drive is; from any other copy,
only for the account whose administrator password was typed. Either way, the
administrator prompt must be approved by the same administrator account that mounted
the drive.

- **Sources:** a local path, a network path (`\\server\share\tools.wim`), or an HTTP or
  HTTPS URL. Only the parts of the WIM you actually read are fetched. Web servers must
  support byte ranges and a strong ETag. Plain HTTP works but warns that the data isn't
  protected in transit; installing drivers or `--run` from plain HTTP also needs `--wim-sha256`.
- **Drive letter:** leave out `--drive` to use the highest free letter, from Z: down.
- **Image:** a WIM can hold several images; `--index 2` picks the second (default 1).
- **Who can open the drive:** the account that mounted it, SYSTEM and elevated
  administrators. Other accounts on the computer are refused. A right-click Mount also lets
  in the account signed in to the desktop where the administrator prompt appeared, so a
  standard user who has an administrator's password typed can open the drive, every file
  in it, not only what the WIM's permissions allow (when Windows can name that account).
  A console mount adds it only with `--from-menu`, which is what the menu passes and is
  shown in the administrator prompt's details. Add `--all-users` to let
  every account open it: each then reads only what the WIM's own stored permissions allow
  it to read (checked by Windows' own access check), so a file only administrators could
  read when the image was captured stays closed to them. A WIM captured without
  permissions (wimlib's `--no-acls`) has none to apply, so every file is open to all.
- **The drive** is read-only and shows the program's icon in Explorer.
- **Format...** appears on the drive's right-click menu because Windows offers it on every
  local disk, and there is no supported way to hide it for one drive. It cannot change
  anything: Windows refuses with "Cannot format. This volume is write protected.", and the
  program only ever opens the WIM file for reading.
- **Network drops:** a short outage of the share or web server does not lose the drive;
  reads are retried for a bounded time, then fail rather than hang. Limit, web WIMs: the
  bound is per read, and one request from Windows (listing a folder, say) can need
  several reads. A server that keeps failing for most of a minute on each of several
  blocks in a row can outlast Windows' own request timeout, and Windows then drops the
  drive instead of the program stopping it cleanly. Either way the mount ends; only the
  clean stop message is missing.
- **Split WIMs (`.swm`):** give the first part (`install.swm`); the others (`install2.swm`,
  `install3.swm`, …) are found beside it and read where they are — nothing is joined or
  copied. This is the naming DISM `/Split-Image` uses. All parts must be present, in
  order, with the same set ID and compression, or the mount is refused. That catches
  mix-ups, not a part someone crafted on purpose: the set ID is not a secret.
  `--wim-sha256` cannot be used with a split WIM, since it checks a single file; to
  trust one, serve it over HTTPS with `--wim-cert-sha256`, and pin what you run with
  `--run-sha256`.
- **Formats:** every kind of WIM that DISM on Windows 11 makes: uncompressed, fast
  (XPRESS), max (LZX), recovery (`.esd`, LZMS) and split `.swm`. Also wimlib's
  `--solid` LZMS WIMs.
- **Alternate data streams appear as separate files.** A file's extra named streams in the
  WIM are not offered as streams: Windows' stream requests (`dir /r`, `Get-Item -Stream`,
  opening `file:stream`) are refused. Each stream is listed beside its file as a plain
  read-only file named `<file>_<stream>` (stream `a` of `notes` is `notes_a`). DokanNet
  2.3.0.3, the library this program uses to talk to Dokan, can crash when a program lists a
  file's streams (dokan-dotnet issue #395); the fix is not in a release yet. A later version
  built with a fixed DokanNet may offer them as streams again.

### Making sure you are reading the right WIM

Three options, from cheapest to strongest:

- `--wim-cert-sha256 <hash>`: only needed in two cases: your own HTTPS server with a
  self-signed certificate, or a network where you trust that one server and nothing in between.
  The program then accepts only the certificate with this fingerprint. It checks who sends the
  file, not the file itself.
- `--wim-sha256 <hash>`: require the whole WIM to match this SHA-256. Proves the bytes,
  so it works even over plain HTTP, and a changed or swapped source stops the mount. It
  reads the entire WIM first, which for a large WIM over a network is the download that
  mounting was meant to avoid.
- `--run-sha256 <hash>`: for `--run`, checks only the program file (see below).

Get a file's SHA-256 with `Get-FileHash C:\Images\tools.wim` in PowerShell, or `certutil -hashfile C:\Images\tools.wim SHA256` in Command Prompt.

## Install, with a right-click Mount

```
.\WimDriverMount.exe --install
```

Copies the program, with the notices it carries and the signed Dokan installer for this PC
(`Dokan_x64.msi` or `Dokan_ARM64.msi`) if one is beside it (a file of that name that is not
a genuine Dokan 2.3 or later 2.x release stops the install), to
`C:\Program Files\WimDriverMount`, checks every copied file, and adds **Mount with WIM
Driver Mount** to the right-click menu of `.wim`, `.swm` and `.esd` files (Windows 11:
*Show more options*). Double-click is left to whatever program already opens WIMs.

Mount works like Windows' Mount on an ISO: the WIM is mounted in the background at the
highest free letter, and File Explorer opens on it. A WIM with several images asks which
one first. Each mount asks for administrator approval, because Dokan drives need it; the
drive keeps its **Unmount with WIM Driver Mount** entry for when you are done. For a split
WIM, right-click the first part.

- **Another folder:** `--install "D:\Program Files\WimDriverMount"`. It must be on a local
  internal disk, reached through no link; its parent must already exist, and only
  administrators may rename things in any folder above it (a folder made by an ordinary
  account, or one in the root of most data disks, is refused). Only the last folder is created.
- **Permissions:** an existing folder only administrators can change is left exactly as
  it is. A new one is made with owner Administrators, full control for Administrators and
  SYSTEM, and read and run for Users, with nothing inherited. An existing folder another
  account can change is refused rather than fixed: whoever has it open keeps that access
  whatever its permissions become. After copying, every file is checked again. (That
  also holds for a folder someone fixed by hand earlier: anyone who had it open then
  may still have it open. A new folder is the safe choice.)
- **Upgrades:** an installed copy of the same or a newer version is kept, and said so;
  add `--force` to replace it. A drive mounted from the installed copy must be unmounted first.
- **The menu** is added for every account on the computer, as the program is installed for
  all of them. A standard user who clicks Mount and has an administrator's password typed
  at the prompt can open the drive too: it is granted to the account signed in to that
  desktop as well as the administrator's. If Windows cannot name that account, it is
  refused; mount from a console with `--all-users` instead.
- **Upgrading from before 0.7.4:** earlier versions added the menu for one account only.
  `--install` and `--uninstall` clear that entry, when it runs the same installed program,
  in the account whose password was typed and in the account that runs them; an
  `--uninstall` run from the installed copy itself clears the second only while the
  machine-wide entry exists (it is put there by a 0.7.4 or later `--install`). An entry left
  in any other account takes precedence over the machine-wide one for that account; it can
  be deleted there: `HKCU\Software\Classes\SystemFileAssociations\<.wim, .swm or .esd>\shell\WimDriverMount.Mount`.
- **Several images:** the menu lists up to 16. For a WIM with more, mount from a console
  with `--index`. The menu is offered for one file at a time.
- **Removing it:** `--uninstall` (or `--uninstall <folder>`) removes the files `--install`
  copied and the menu entry, and leaves anything else in the folder. Run from the
  installed copy itself, the program and its folder go when Windows next restarts. Where
  ordinary accounts can create folders beside it (in C:\, say), the emptied folder is kept,
  so nobody can put a program of their own where a menu entry an earlier version added in
  another account may still point.

## Run a program from a WIM

```
.\WimDriverMount.exe --wim https://server/tools.wim --run Tools\setup.exe --run-args "/quiet /log C:\Temp\setup.log"
```

This mounts the WIM, runs the program from the drive with its own folder as the working
directory, waits for it to exit, unmounts, and returns the program's exit code. Use it for
installers and tools you keep in a WIM instead of copying them to every machine. The path
is relative to the root of the WIM, and must name a `.exe`, `.com`, `.bat` or `.cmd` file
(for an MSI, run a `.cmd` that calls `msiexec`).

The program runs with this tool's administrator rights, so check what you run:

- `--run-sha256 <hash>` refuses to start the program unless its file matches that hash,
  and the drive then serves exactly the checked bytes. Only that one file is checked:
  DLLs and other files beside it are not.
- For a WIM you do not fully trust, use `--wim-sha256`, which covers every byte. It
  cannot be used with a split WIM; there, `--run-sha256` is what checks the program.
- `--run` refuses plain HTTP unless `--wim-sha256` is given.

## Run the same mounts every time

For the same mounts on many machines, or as part of a script, put them in a settings file
(INI). A key is a mount option without its dashes (`wim`, `drive`, `index`, `run`,
`install-drivers` and so on). Commands such as `unmount`, and `test-mount`, are not settings.
`[defaults]` applies to every mount and a mount's own key wins (`log` and `evtlog` go only
in `[defaults]`).

```ini
; C:\Config\mounts.ini
[defaults]
index = 1

[mount:vmware]
wim = \\server\images\vmware.wim
drive = V

[mount:dell]
wim = https://images.corp.local/dell.wim
; PowerShell: (Get-FileHash dell.wim).Hash   Command Prompt: certutil -hashfile dell.wim SHA256
wim-sha256 = <the WIM's 64-digit SHA-256>
drive = W
install-drivers = true
background = false
```

```
.\WimDriverMount.exe --protect-config C:\Config\mounts.ini
.\WimDriverMount.exe --mount-config C:\Config\mounts.ini
```

Mounts run in file order. A plain mount is left mounted in the background. A mount that
installs drivers, previews drivers or runs a program runs in the foreground, in turn; it
needs no setting for that, and `background = false` is allowed only on those.
Every mount is checked against the real option rules, with a line number, before the first
one starts, so a mistake on the last mount cannot leave the earlier ones running.

A mount that runs a program or installs drivers must pin the whole WIM with
`wim-sha256`. The settings file is protected; the WIM it names may not be, and whoever
could change that WIM would otherwise choose what runs as administrator, or which driver
is installed. `run-sha256` alone is not enough here: Windows loads a program's DLLs from
its own folder first, and those are not checked. (So a settings file cannot run a
program or install drivers from a split WIM, which `wim-sha256` cannot check.)

The settings file must be on an internal disk: a drive Windows reports as local and fixed,
whose disk is not on USB, FireWire, an SD/MMC bus or iSCSI, and is not a virtual disk
(VHD/VHDX, such as a Dev Drive stored in a VHDX file). USB hard disks call themselves fixed.
On a share, an external disk or an attached virtual disk its permissions may have been set
on another machine (a hostile server can report any owner), so they prove nothing here;
copy the file to a local folder.
A volume Windows will not describe, such as one spanning several disks, is refused too.

**Why `--protect-config`.** A settings file can install drivers and run programs with
administrator rights, so it is refused unless only administrators can change it — the
file *and* its folder, since write access to the folder is enough to replace the file.
Your own account does not count as an administrator here: it also runs unelevated, and
any program you run without elevation could then rewrite the file. Windows makes you the
owner of a file you create, even elevated, so a settings file you wrote needs
`--protect-config` once; it makes the Administrators group the owner.
Under `%ProgramFiles%` the folder permissions are already right, but `--protect-config` will
not change anything there, so a file you write there stays owned by you and is refused; use a
folder of its own such as `C:\Config` instead. Two other obvious places are unsafe: a folder created at the
root of `C:` lets Authenticated Users write, and a new folder under `C:\ProgramData` lets
Users write. `--protect-config` sets the file and its folder (nothing else) to
administrators and SYSTEM only, prints the permissions before and after, and prints the
file's SHA-256 and contents: protecting makes the file trustworthy from now on, but anyone
who could write it before could have changed it, so read what it says. It refuses:

- a file another program has open for writing (close it and try again);
- a file or folder that an account other than you, administrators or SYSTEM owns or may
  change the permissions of: such an account may already hold a handle that keeps that power after
  protecting, and nothing can take it away. Have an administrator create a new folder
  and file instead. Permissions tightened by hand earlier, while someone held such a
  handle, cannot be detected;
- a file not on an internal disk (see above);
- a folder reached through a link or junction;
- a drive root; anything inside Windows or Program Files; ProgramData and Temp
  themselves; a user profile, or any folder directly in one (`C:\Users\<name>\Config` too);
- a folder that holds other folders.

Give the settings file a folder of its own, such as `C:\Config`.

## If something went wrong

| What you see | Do this |
|---|---|
| A background drive won't go away | `.\WimDriverMount.exe --unmount M:` |
| After a restart, a drive letter is "in use" by an old mount | `.\WimDriverMount.exe --unmount M:` clears the leftover record. A new background mount on M: also clears it when the old mount has provably ended, says so, and reports how that mount left Dokan |
| `--unmount M:` says to, or a new mount on M: says it already has a background mount record that `--unmount M:` does not clear | `.\WimDriverMount.exe --resume-worker-cleanup M:` |
| You want to see what an interrupted driver install recorded | `.\WimDriverMount.exe --inspect-driver-journal <ID>`, with the ID printed when the install started |
| The journal is in ProgramData | `.\WimDriverMount.exe --inspect-legacy-driver-journal <ID>` |

Journal inspection only reads, and never retries anything. It says whether the journal is
consistent, how many calls finished, whether one was left unfinished and whether a restart
was recorded; it does not name devices or packages, and cannot say what Windows changed. 

**Logs.** Two optional logs, both off unless you ask:

- `--log <path>` appends this run's messages to a text file, each line with the date,
  time and process number, for example `--log C:\Logs\wim.log`. A background mount keeps
  writing to the same file, including why it failed if it does. The output of a program
  started with `--run` is not included. The folder must already exist. Give its real
  path: a link, a junction or a SUBST drive letter on the way is refused (on the command
  line a mapped network drive is turned into its `\\server\share` path; in a settings
  file, write the `\\server\share` path yourself). If the file cannot be opened
  safely, the run warns and carries on without it; when the folder is one only
  administrators can write and the command asks for administrator rights, the
  administrator copy tries it again and logs from there.
- `--evtlog` also writes plain-sentence entries to the Windows Application event log
  (source WIM Driver Mount): IDs 1000–1005 for success, 2000–2005 for failure, 2900 for
  failure details from a background mount or from removing Dokan (error types and codes
  only). If an entry cannot be written, the run says so; its result and exit code stand.

In a settings file they are `log = C:\Logs\wim.log` (a full path) and `evtlog = true`, and
they go in `[defaults]`: they apply to the whole run.

## Dokan

Mounting uses Dokan, a free driver that lets a program provide a drive. The download
includes Dokan's installer, `Dokan_x64.msi` (`Dokan_ARM64.msi` on ARM64), beside
`WimDriverMount.exe`, so an offline computer needs no internet (unless `--get-dokan`
is used without a local file or share). The first mount installs
Dokan, from the first of these that applies:

1. `--get-dokan <source>`: the installer at that path, network path, or HTTPS URL.
2. `--get-dokan` on its own: the release this program is tested with (Dokan 2.3.1),
   downloaded from GitHub and checked against its exact SHA-256. In a settings file,
   write `get-dokan = tested`.
3. `Dokan_x64.msi` (`Dokan_ARM64.msi` on ARM64) beside `WimDriverMount.exe`.
4. The latest official release, downloaded from GitHub.

Whichever it is, it is installed only if Windows accepts its signature, the signer is
Dokan's publisher (LEOSAC, matched exactly by organisation and French company
registration number), and the package declares Dokan's own upgrade code and version 2.3
or a later 2.x. Any official
signed release therefore works — from a file share, a USB stick or an archive — and a
tampered or look-alike one is refused. Only `--get-dokan` on its own is pinned to one
build's hash; otherwise newer 2.x releases are accepted, so Dokan's fixes reach you.
`--get-dokan` is used only when Dokan is not installed: if a newer Dokan ever breaks
mounting, uninstall it in Settings > Apps, restart Windows, then run with `--get-dokan` on
its own to install the tested one.
Certificate revocation is not checked. `--no-install-dokan` refuses to install at all.

**Dokan stays installed** for later runs.

`--remove-dokan` uninstalls it after that run, if WIM Driver Mount installed it (a Dokan
you installed yourself is left alone, as is one another mount is still using). After Dokan has
mounted a drive, removing it (measured with Dokan 2.3.0) leaves its driver loaded until
Windows restarts, and installing it again before then fails. The run says so, and a mount
tried before that restart says so too while Windows reports the driver still stopping.

## Results and elevation

Operations ask for administrator approval. Typed in a console (PowerShell, Command Prompt,
Terminal), the work then runs hidden and its output appears in that same window: no second
window, nothing to press, and the command returns the real exit code. `--help`, `--version`,
`--preview-drivers` and journal inspection need no approval at all. Output redirected to a
file (`> log.txt`) still goes to the screen this way; to capture it, run from an
administrator console.

Dropped onto the program or started by double-click, there is no console to share, so the
work runs in an administrator window of its own, which waits for Enter at the end; add
`--no-pause` to have it close by itself (the exit code then tells you how it went).

The first time a newly downloaded copy asks for approval, the prompt can take tens of
seconds to appear (measured: 44 seconds on one PC, then 3 seconds for the same file, and
under half a second for a copy not marked as downloaded). No prompt appears meanwhile. This is
Windows checking the file before it elevates it, most likely Microsoft Defender's first-time
cloud check of an unsigned program it has not seen; this program has already made its
request by then. Later runs of the same file are quick.

The right-click **Unmount with WIM Driver Mount** shows no console window: only the
administrator prompt, then nothing if it worked. If it fails, or Windows must restart
afterwards, a message box says so.

Exit codes:

| Code | Meaning |
|---|---|
| 0 | Success |
| 3010 | Restart required |
| 1 | Failed, or the outcome is unknown |
| 2 | Journal inspection was given something that is not a journal ID |
| other | With `--run`, the program's own exit code (a settings-file run returns 1 instead, and names the program's code; there a program's 3010 counts as restart required). A single `--run` whose program exits 3010 cannot be told from "restart required" by the code alone; the run prints "The program exited with code 3010." when it was the program. |

`--whatif` checks a command without mounting or installing anything: it opens the WIM
read-only, reads the chosen image, checks Dokan, and says what it would do. It still asks
for administrator approval, and cannot be combined with `--run`.

## Known limits: your own environment variables and console

When Windows starts WIM Driver Mount with administrator rights, it gives it your account's
environment variables, and any program you run without elevation can change those
(they are stored in `HKCU\Environment`). Two kinds matter here:

- **.NET runtime settings.** Variables such as `CORECLR_ENABLE_PROFILING` and
  `DOTNET_DiagnosticPorts` can make the .NET runtime load other code as it starts, before
  WIM Driver Mount runs its first line, so it cannot check or refuse them. That code then
  runs with administrator rights. (Startup hooks, `DOTNET_STARTUP_HOOKS`, are switched off
  in this build.)
- **Variables in `--run` arguments.** A `.bat` or `.cmd` program is started through
  Command Prompt, which expands `%NAME%` in its arguments. A value you did not expect can
  change what that command does.

This is not specific to WIM Driver Mount: the same variables affect every elevated .NET
program, and every elevated batch file, you start. If programs you run without elevation
might be hostile, check `HKCU\Environment` before approving the administrator prompt, and
avoid `%NAME%` in `run-args`.

**Sharing your console.** When the work writes into the window you typed in, any program
you run without elevation can also attach to that window and send it Ctrl+C, which stops
the work at that moment, as a power cut would. Nothing is ever read from that window, and
for that reason a program started with `--run` opens in a window of its own (which closes
when it exits). Ctrl+C in your window does not reach that program; close its window, or the
program, to end it, and the mount closes after it. An interrupted driver install can be checked with `--inspect-driver-journal`.

## Build

You need a Windows PC with an x64 processor, the
[.NET 9 SDK](https://dotnet.microsoft.com/download/dotnet/9.0), and internet access (the build
downloads its NuGet packages). An x64 PC builds for x64 and for ARM64 PCs alike.

1. Download Dokan's installer from its
   [2.3.1.1000 release](https://github.com/dokan-dev/dokany/releases/tag/v2.3.1.1000):
   `Dokan_x64.msi` for x64 PCs, `Dokan_ARM64.msi` for ARM64 PCs. The build checks it against
   the SHA-256 it expects and puts it beside the program, so the PC you run it on needs no
   internet to install Dokan.
2. Open PowerShell in the repository's folder and run one of these, with the installer's path:

   ```powershell
   .\src\build.ps1 -DokanMsiPath C:\Downloads\Dokan_x64.msi                      # for x64 PCs
   .\src\build.ps1 -Runtime win-arm64 -DokanMsiPath C:\Downloads\Dokan_ARM64.msi  # for ARM64 PCs
   ```

   If PowerShell refuses to run scripts, run it as
   `powershell -ExecutionPolicy Bypass -File .\src\build.ps1 -DokanMsiPath ...`.
3. The program and everything it needs are in `src\publish` (or the folder you name with
   `-OutputPath`). Copy that folder to the PC and run `WimDriverMount.exe`.

Try it on a test machine or VM before a real one: it runs as administrator and installs
drivers.