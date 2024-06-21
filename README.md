An NSS module to use Windows' DNS resolution in WSL1.

WSL's hostname resolution is done by glibc, which sends regular DNS queries. This can interact poorly with Windows VPN software, which, in the interest of not leaking your traffic, can intercept or drop the queries. This library tells glibc to instead communicate with a Windows program that asks Windows to resolve the hostname directly, which works much better.

## Step 1: Build and install the Linux library

In the repo root, run the following commands to build the Linux library:

```sh
cmake -S linux -B linux-build -DCMAKE_BUILD_TYPE=Release
cmake --build linux-build --target nss_windns
```

This will create the file `libnss_windns.so.2` in the `linux-build` directory. This file needs to be copied alongside the other nss libraries, which are usually in `/lib` or `/usr/lib`. Look for files named `libnss_files.so.2` and `libnss_dns.so.2`, and use whatever directory those are in.

## Step 2: Build the Windows library

### Building with Visual Studio

Make sure cmake is installed via the Visual Studio installer. Then, from the Visual Studio command prompt, navigate to the repo root and run the following commands:

```cmd
cmake -S windows -B windows-build
cmake --build windows-build --target windns_proxy --config Release
```

This will create the file `windows-build\Release\windns_proxy.exe`. Put this file wherever you want.

### Building with mingw

TODO: mingw toolchain file instructions

This will create the file `windows-build\windns_proxy.exe`. Put this file wherever you want. Make sure to copy whatever dlls your mingw runtime needs to the same directory as the executable, or else it will not run.

## Step 3: Set up the connection

### Step 3.1 Start the Windows program

The two programs communicate over a unix socket, which has to reside somewhere in your filesystem. Pick a location your user can write to. You should avoid placing the socket in your temp directory, since it may be automatically deleted by cleanup programs. Once you have decided on a location for the socket, create it by running `windns_proxy.exe` with that path as an argument (e.g. `windns_proxy.exe "C:\Users\me\windns.socket"`).

If you want to run the proxy whenever you log in, create a shortcut that runs the desired command and follow [Microsoft's instructions](https://support.microsoft.com/en-us/windows/add-an-app-to-run-automatically-at-startup-in-windows-10-150da165-dcd9-7230-517b-cf3c295d89dd) to make it run automatically.

### Step 3.2 Tell Linux where the socket is

The library can determine the path one of two ways; either via the `NSS_WINDNS_SOCKET` environment variable, or via a symlink at `$HOME/.windns.socket`. The environment variable takes precedence over the symlink. The value/target should be the path of the socket you chose in step 3.1. Note that this should be a Linux path, not a Windows path (e.g. it should start with `/mnt/c/` instead of `C:\`). If in doubt, you can use `wslpath` to convert the Windows path into a Linux path.

### Step 3.3 Tell glibc to use the library

As root, edit the file `/etc/nsswitch.conf`. Find the line starting with "hosts:", and on that line, replace the word "dns" with "windns"
