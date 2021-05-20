#!/bin/bash -p
# Hide shell commands from expect \
#set -x;\
export argv0=$(basename $0);\
exec expect -- "$0" "$@"

#exp_internal 1
#strace 4

proc main {argc argv} \
{
  global env

  set argv0 $env(argv0)
  set pattern {}
  set num_pkts 0                   ;# default 1 pkt (for testing)
  set report_count 0

  puts "$argc args: $argv"

  # Get options
  while {$argc} \
  {
    switch -- [lindex $argv 0] \
    {
      -f \
      {
        chkarg $argc $argv
        set pfile [lindex $argv 1]
        if {![file readable $pfile]} {puts "\n$pfile: not readable\n"; exit 1}
        file stat $pfile stat
        if {[string compare $stat(type) file]} \
        {
          puts "\n$pfile: not a regular file\n"
          exit 1
        }
        set pchan [open $pfile]
        if {[gets $pchan pattern] < 0} {puts "\n$pfile: read error\n"; exit 1}
        close $pchan
        set argv [lreplace $argv 0 1]
        incr argc -2
      }

      -h {help 0}

      -n \
      {
        chkarg $argc $argv
        set num_pkts [expr [lindex $argv 1] + 0]
        set argv [lreplace $argv 0 1]
        incr argc -2
      }

      -p \
      {
        chkarg $argc $argv
        set pattern [lindex $argv 1]
        set argv [lreplace $argv 0 1]
        incr argc -2
      }

      -r \
      {
        chkarg $argc $argv
        set report_count [expr [lindex $argv 1] + 0]
        set argv [lreplace $argv 0 1]
        incr argc -2
      }

      default {puts "\n[lindex $argv 0] unrecognised"; help 1}
    }                              ;# switch
  }                                ;# while

  if {![string length $pattern]} \
  {
    puts "\nNo pattern supplied"
    help 1
  }                                ;# if {![string length $pattern]}

  spawn nc -6 -l -u 1042
  #sleep 1
  set recv_id $spawn_id
  spawn nc -6 -u ::1 1042
  #sleep 1
  set send_id $spawn_id
  set spawn_id $recv_id

  set idx_wdth [string length $num_pkts]

  for {set pkt_idx 0} {$num_pkts >= 0} {incr num_pkts -1; incr pkt_idx} \
  {
  set pkt_idx_fmtd [format %0${idx_wdth}d $pkt_idx]
    exp_send -i $send_id "$pattern $pkt_idx_fmtd\r"
    expect \
    {
      -timeout 1
      timeout {puts "Missed $pkt_idx_fmtd"}
      $pkt_idx_fmtd\r\n
    }
    if {!$pkt_idx} {log_user 0}
    if {$report_count && !($pkt_idx % $report_count)} \
    {puts -nonewline $pkt_idx_fmtd\r; flush stdout}
  }                                ;# for
  if {$report_count} {puts {}}

  log_user 1
  exp_send -i $send_id q\r
  sleep 1
}                                  ;# main

proc chkarg {argc argv} \
{
  if {$argc == 1} \
  {
    puts "\nMissing [lindex $argv 0] argument"
    help 1
  }                                ;# if {$argc == 1}
}                                  ;# chkarg

proc help exitcode \
{
  global env
  set argv0 $env(argv0)

  set s [string length $argv0]
  set sp {}
  for {} {$s} {incr s -1} {set sp "$sp "}

  puts {}
  puts "Usage: $argv0 -p pattern | -f pattern_file | -e env_var_name"
  puts "       $sp \[-n last_pkt\] \[-r report_interval \]"
  puts "       $argv0 -h"
  puts "  -e <name>: Pattern to send is env(<name>) NOT YET IMPLEMENTED (NYI)"
  puts "  -f <file>: <file> contains pattern to send"
  puts "             If <file> has multiple lines, send packets in sequence NYI"
  puts -nonewline "             N.B. Same applies to multiple patterns "
  puts "specifiled by any method NYI"
  puts "  -h: give this Help and exit"
  puts "  -n <n>: send pkts 0 - <n>"
  puts "  -p <text>: Send <text> as pattern"
  puts "  -r <n>: Update display of pkts sent every <n> pkts"
  puts {}

  exit $exitcode
}                                  ;# help

main $argc $argv
