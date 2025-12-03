import win32evtlog  # requires to have pywin32 installed.
import win32api
import win32con
import win32security
import pywintypes
# needed for the security permission (but still requires to run as admin).
import ctypes
import os  # modules for checking admin rights
import argparse


def checkforAdminRights():
    try:
        return os.getuid() == 0
    except AttributeError:
        return ctypes.windll.shell32.IsUserAnAdmin()


def securityPermission():
    privName = "SeSecurityPrivilege"
    privs = win32security.LookupPrivilegeValue(None, privName)
    newPrivs = [(privs, win32con.SE_PRIVILEGE_ENABLED)]

    token = win32security.OpenProcessToken(win32api.GetCurrentProcess(
    ), win32con.TOKEN_ADJUST_PRIVILEGES | win32con.TOKEN_QUERY)
    win32security.AdjustTokenPrivileges(token, False, newPrivs)


def getTotalsOfSource(server, source):
    evtHandle = win32evtlog.OpenEventLog(server, source)
    total = win32evtlog.GetNumberOfEventLogRecords(evtHandle)
    print("Logs in %s= % d\n" % (source, total))
    win32evtlog.CloseEventLog(evtHandle)


def readEventLogs(server, args):
    evtHandle = None
    try:
        # reads oldest to newest by dafault, unless specific by user args to be reversed.
        flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        if (args.reverse):
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
        evtHandle = win32evtlog.OpenEventLog(server, args.source)
        count = 0
        while 1:
            logs = win32evtlog.ReadEventLog(evtHandle, flags, 0)
            if not logs:
                break
            for event in logs:
                if count == args.max:
                    return
                print(f"evtID: {event.EventID & 0xFFFF}\ntime: {event.TimeGenerated.Format()}\nsource: {event.SourceName}\n"
                      f"evtCat: {event.EventCategory}\ncomputer: {event.ComputerName}\n"
                      f"recNo: {event.RecordNumber}\ntext: {event.StringInserts or []}")
                print("\n"+"_"*60)
                count += 1

    except SystemExit as e:
        print(f"Error: {e}")
    except pywintypes.error as e:
        print(f"Error reading logs: {e}")
    except win32evtlog.error as e:
        print(f"Error reading logs: {e}")
    finally:
        if evtHandle:
            win32evtlog.CloseEventLog(evtHandle)


def main(server, args):
    print("Source:")
    if not checkforAdminRights():
        print("Error: This program must run as administrator")
        return
    securityPermission()
    getTotalsOfSource(server, args.source)
    readEventLogs(server, args)


def addArgs():
    pars = argparse.ArgumentParser(
        prog='loganalyzer')
    pars.add_argument(
        '-s', '--source', help='the window log source to read from. sources available : [application, system, security]', required=True)
    pars.add_argument(
        '-m', '--max', help='maximum logs to be displayed. (default = 10)', type=int, default=10)
    pars.add_argument('-r', '--reverse',
                      help='read in reverse or backwards.', action='store_true')

    return pars.parse_args()


if __name__ == "__main__":
    server = None
    args = addArgs()
    main(server, args)
