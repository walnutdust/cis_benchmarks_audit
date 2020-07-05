#!/bin/bash

##
## Copyright 2019 Andy Dustin
## Modified Copyright 2020 Garett Tok
##
## Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except 
## in compliance with the License. You may obtain a copy of the License at
##
## http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software distributed under the License is 
## distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and limitations under the License.
##

## This script checks for compliance against CIS CentOS Linux 7 Benchmark v2.1.1 2017-01-31 measures
## Each individual standard has it's own function and is forked to the background, allowing for 
## multiple tests to be run in parallel, reducing execution time.

## You can obtain a copy of the CIS Benchmarks from https://www.cisecurity.org/cis-benchmarks/


### Variables ###
## This section defines global variables used in the script
args=$@
count=0
exit_code=0
me=$(basename $0)
result=Fail
state=0
tmp_file_base="/tmp/.cis_audit"
tmp_file="$tmp_file_base-$(date +%y%m%d%H%M%S).output"
started_counter="$tmp_file_base-$(date +%y%m%d%H%M%S).started.counter"
finished_counter="$tmp_file_base-$(date +%y%m%d%H%M%S).finished.counter"
wait_time="0.25"
progress_update_delay="0.1"
max_running_tests=10
debug=False
trace=False
renice_bool=True
renice_value=5
start_time=$(date +%s)
color=True
test_level=0
cnf_files=("$(/usr/sbin/mysqld --help --verbose | grep .cnf | head -n 1)");
user="root"


### Functions ###
## This section defines functions used in the script 
is_test_included() {
    id=$1
    level=$2
    state=0
    
    write_debug "Checking whether to run test $id"
    
    [ -z $level ] && level=$test_level
    
    ## Check if the $level is one we're going to run
    if [ $test_level -ne 0 ]; then
        if [ "$test_level" != "$level" ]; then
            write_debug "Excluding level $level test $id"
            state=1
        fi
    fi
    
    ## Check if there were explicitly included tests
    if [ $(echo "$include" | wc -c ) -gt 3 ]; then
        
        ## Check if the $id is in the included tests
        if [ $(echo " $include " | grep -c " $id ") -gt 0 ]; then
            write_debug "Test $id was explicitly included"
            state=0
        elif [ $(echo " $include " | grep -c " $id\.") -gt 0 ]; then
            write_debug "Test $id is the parent of an included test"
            state=0
        elif [ $(for i in $include; do echo " $id" | grep " $i\."; done | wc -l) -gt 0 ]; then
            write_debug "Test $id is the child of an included test"
            state=0
        elif [ $test_level == 0 ]; then
            write_debug "Excluding test $id (Not found in the include list)"
            state=1
        fi
    fi
    
    ## If this $id was included in the tests check it wasn't then excluded
    if [ $(echo " $exclude " | grep -c " $id ") -gt 0 ]; then
        write_debug "Excluding test $id (Found in the exclude list)"
        state=1
    elif [ $(for i in $exclude; do echo " $id" | grep " $i\."; done | wc -l) -gt 0 ]; then
        write_debug "Excluding test $id (Parent found in the exclude list)"
        state=1
    fi
    
    [ $state -eq 0 ] && write_debug "Including test $id"
    
    return $state
} ## Checks whether to run a particular test or not
get_id() {
    echo $1 | sed -e 's/test_//' -e 's/\.x.*$//'
} ## Returns a prettied id for a calling function
help_text() {
    cat  << EOF |fmt -sw99
This script runs tests on the system to check for compliance against the CIS CentOS 7 Benchmarks.
No changes are made to system files by this script.

  Options:
EOF

    cat << EOF | column -t -s'|'
||-h,|--help|Prints this help text
|||--debug|Run script with debug output turned on
|||--level (1,2)|Run tests for the specified level only
|||--include "<test_ids>"|Space delimited list of tests to include
|||--exclude "<test_ids>"|Space delimited list of tests to exclude
|||--nice |Lower the CPU priority for test execution. This is the default behaviour.
|||--no-nice|Do not lower CPU priority for test execution. This may make the tests complete faster but at 
||||the cost of putting a higher load on the server. Setting this overrides the --nice option.
|||--no-colour|Disable colouring for STDOUT. Output redirected to a file/pipe is never coloured.
|||--user|MySQL user name

EOF

    cat << EOF

  Examples:
  
    Run with debug enabled:
      $me --debug
      
    Exclude tests from section 1.1 and 1.3.2:
      $me --exclude "1.1 1.3.2"
      
    Include tests only from section 4.1 but exclude tests from section 4.1.1:
      $me --include 4.1 --exclude 4.1.1
    
    Run only level 1 tests
      $me --level 1
    
    Run level 1 tests and include some but not all SELinux questions
      $me --level 1 --include 1.6 --exclude 1.6.1.2

EOF

exit 0

} ## Outputs help text
now() {
    echo $(( $(date +%s%N) / 1000000 ))
} ## Short function to give standardised time for right now (saves updating the date method everywhere)
outputter() {
    write_debug "Formatting and writing results to STDOUT"
    echo
    echo " CIS MySQL Community Server 5.7 Benchmark v1.0.0 Results "
    echo "---------------------------------------"
    
    if [ -t 1 -a $color == "True" ]; then
        (
            echo "ID,Description,Scoring,Level,Result,Duration"
            echo "--,-----------,-------,-----,------,--------"
            sort -V $tmp_file
        ) | column -t -s , |\
            sed -e $'s/^[0-9]\s.*$/\\n\e[1m&\e[22m/' \
                -e $'s/^[0-9]\.[0-9]\s.*$/\e[1m&\e[22m/' \
                -e $'s/\sFail\s/\e[31m&\e[39m/' \
                -e $'s/\sPass\s/\e[32m&\e[39m/' \
                -e $'s/^.*\sSkipped\s.*$/\e[2m&\e[22m/'
    else
        (
            echo "ID,Description,Scoring,Level,Result,Duration"
            sort -V $tmp_file
        ) | column -t -s , | sed -e '/^[0-9]\ / s/^/\n/'
    fi
    
    tests_total=$(grep -c "Scored" $tmp_file)
    tests_skipped=$(grep -c ",Skipped," $tmp_file)
    tests_ran=$(( $tests_total - $tests_skipped ))
    tests_passed=$(egrep -c ",Pass," $tmp_file)
    tests_failed=$(egrep -c ",Fail," $tmp_file)
    tests_errored=$(egrep -c ",Error," $tmp_file)
    tests_duration=$(( $( date +%s ) - $start_time ))
    
    echo
    echo "Passed $tests_passed of $tests_total tests in $tests_duration seconds ($tests_skipped Skipped, $tests_errored Errors)"
    echo
    
    write_debug "All results written to STDOUT"
} ## Prettily prints the results to the terminal
parse_args() {
    args=$@
    
    ## Call help_text function if -h or --help present
    $(echo $args | egrep -- '-h' &>/dev/null) && help_text
    
    ## Check arguments for --debug
    $(echo $args | grep -- '--debug' &>/dev/null)  &&   debug="True" || debug="False"
    write_debug "Debug enabled"
    
    ## Full noise output
    $(echo $args | grep -- '--trace' &>/dev/null) &&  trace="True" && set -x
    [ $trace == "True" ] && write_debug "Trace enabled"
    
    ## Renice / lower priority of script execution
    $(echo $args | grep -- '--nice' &>/dev/null)  &&   renice_bool="True"
    $(echo $args | grep -- '--no-nice' &>/dev/null)  &&   renice_bool="False"
    [ $renice_bool == "True" ] && write_debug "Tests will run with reduced CPU priority"
    
    ## Disable colourised output
    $(echo $args | egrep -- '--no-color|--no-colour' &>/dev/null)  &&   color="False" || color="True"
    [ $color == "False" ] && write_debug "Coloured output disabled"
    
    ## Check arguments for --exclude
    ## NB: The whitespace at the beginning and end is required for the greps later on
    exclude=" $(echo "$args" | sed -e 's/^.*--exclude //' -e 's/--.*$//') "
    if [ $(echo "$exclude" | wc -c ) -gt 3 ]; then
        write_debug "Exclude list is populated \"$exclude\""
    else
        write_debug "Exclude list is empty"
    fi
    
    ## Check arguments for --include
    ## NB: The whitespace at the beginning and end is required for the greps later on
    include=" $(echo "$args" | sed -e 's/^.*--include //' -e 's/--.*$//') "
    if [ $(echo "$include" | wc -c ) -gt 3 ]; then
        write_debug "Include list is populated \"$include\""
    else
        write_debug "Include list is empty"
    fi
    
    ## Check arguments for --level
    if [ $(echo $args | grep -- '--level 2' &>/dev/null; echo $?) -eq 0 ]; then
        test_level=$(( $test_level + 2 ))
        write_debug "Going to run Level 2 tests"
    fi
    if [ $(echo $args | grep -- '--level 1' &>/dev/null; echo $?) -eq 0 ]; then
        test_level=$(( $test_level + 1 ))
        write_debug "Going to run Level 1 tests"
    fi
    if [ "$test_level" -eq 0 -o "$test_level" -eq 3 ]; then
        test_level=0
        write_debug "Going to run tests from any level"
    fi
    
    ## Check arguments for --user
    ## NB: The whitespace at the beginning and end is required for the greps later on
    if [[ $(echo "$args" | sed -e 's/^.*--user //' -e 's/--.*$//' | wc -c ) -gt 0 ]]; then
        user=$(echo "$args" | sed -e 's/^.*--user //' -e 's/--.*$//')
    fi
} ## Parse arguments passed in to the script
progress() {
    ## We don't want progress output while we're spewing debug or trace output
    write_debug "Not displaying progress ticker while debug is enabled" && return 0
    [ $trace == "True" ] && return 0
    
    array=(\| \/ \- \\)
    
    while [ "$(running_children)" -gt 1 -o "$(cat $tmp_file_base-stage)" == "LOADING" ]; do 
        started=$( wc -l $started_counter | awk '{print $1}' )
        finished=$( wc -l $finished_counter | awk '{print $1}' )
        running=$(( $started - $finished ))
        
        tick=$(( $tick + 1 ))
        pos=$(( $tick % 4 ))
        char=${array[$pos]}
        
        script_duration="$(date +%T -ud @$(( $(date +%s) - $start_time )))"
        printf "\r[$script_duration] ($char) $finished of $started tests completed " >&2
        
        #ps --ppid $$ >> ~/tmp/cis-audit
        #running_children >> ~/tmp/cis-audit
        #echo Stage: $test_stage >> ~/tmp/cis-audit
        
        sleep $progress_update_delay
    done
    
    ## When all tests have finished, make a final update
    finished=$( wc -l $finished_counter | awk '{print $1}' )
    script_duration="$(date +%T -ud @$(( $(date +%s) - $start_time )))"
    #printf "\r[✓] $finished of $finished tests completed\n" >&2
    printf "\r[$script_duration] (✓) $started of $started tests completed\n" >&2
} ## Prints a pretty progress spinner while running tests
run_test() {
    id=$1
    level=$2
    test=$3
    args=$(echo $@ | awk '{$1 = $2 = $3 = ""; print $0}' | sed 's/^ *//')
    
    if [ $(is_test_included $id $level; echo $?) -eq 0 ]; then
        write_debug "Requesting test $id by calling \"$test $id $args &\""
        
        while [ "$(pgrep -P $$ 2>/dev/null | wc -l)" -ge $max_running_tests ]; do 
            write_debug "There were already max_running_tasks ($max_running_tests) while attempting to start test $id. Pausing for $wait_time seconds"
            sleep $wait_time
        done
        
        write_debug "There were $(( $(pgrep -P $$ 2>&1 | wc -l) - 1 ))/$max_running_tests max_running_tasks when starting test $id."
        
        ## Don't try to thread the script if trace or debug is enabled so it's output is tidier :)
        if [ $trace == "True" ]; then
            $test $id $level $args
            
        elif [ $debug == "True" ]; then
            set -x
            $test $id $level $args
            set +x
            
        else
            $test $id $level $args &
        fi
    fi
    
    return 0
} ## Compares test id against includes / excludes list and returns whether to run test or not
running_children() {
    ## Originally tried using pgrep, but it returned one line even when output was "empty"
    search_terms="PID|ps$|grep$|wc$|sleep$"

    [ $debug == True ] && ps --ppid $$ | egrep -v "$search_terms"
    ps --ppid $$ | egrep -v "$search_terms" | wc -l
} ## Ghetto implementation that returns how many child processes are running
setup() {
    write_debug "Script was started with PID: $$"
    if [ $renice_bool = "True" ]; then
        if [ $renice_value -gt 0 -a $renice_value -le 19 ]; then
            renice_output="$(renice +$renice_value $$)"
            write_debug "Renicing $renice_output"
        fi
    fi
    
    write_debug "Creating tmp files with base $tmp_file_base*"
    cat /dev/null > $tmp_file
    cat /dev/null > $started_counter
    cat /dev/null > $finished_counter
} ## Sets up required files for test
test_start() {
    id=$1
    level=$2
    
    write_debug "Test $id started"
    echo "." >> $started_counter
    write_debug "Progress: $( wc -l $finished_counter | awk '{print $1}' )/$( wc -l $started_counter | awk '{print $1}' ) tests."
    
    now
} ## Prints debug output (when enabled) and returns current time
test_finish() {
    id=$1
    start_time=$2
    duration="$(( $(now) - $start_time ))"
    
    write_debug "Test "$id" completed after "$duration"ms"
    echo "." >> $finished_counter
    write_debug "Progress: $( wc -l $finished_counter | awk '{print $1}' )/$( wc -l $started_counter | awk '{print $1}' ) tests."
    
    echo $duration
} ## Prints debug output (when enabled) and returns duration since $start_time
test_stage() {
    echo $test_stage
} ## Shim to get up to date $test_stage value
tidy_up() {
    [ $debug == "True" ] && opt="-v"
    rm $opt "$tmp_file_base"* 2>/dev/null
} ## Tidys up files created during testing
write_cache() {
    write_debug "Writing to $tmp_file - $@"
    printf "$@\n" >> $tmp_file
} ## Writes additional rows to the output cache
write_debug() {
    [ $debug == "True" ] && printf "[DEBUG] $(date -Ins) $@\n" >&2
} ## Writes debug output to STDERR
write_err() {
    printf "[ERROR] $@\n" >&2
} ## Writes error output to STDERR
write_result() {
    write_debug "Writing result to $tmp_file - $@"
    echo $@ >> $tmp_file
} ## Writes test results to the output cache


### Benchmark Tests ###
## This section defines the benchmark tests that are called by the script

## Tests used in multiple sections
skip_test() {
    ## This function is a blank for any tests too complex to perform 
    ## or that rely too heavily on site policy for definition
    
    id=$1
    level=$2
    description=$( echo $@ | awk '{$1=$2=""; print $0}' | sed 's/^ *//')
    scored="Skipped"
    result=""

    write_result "$id,$description,$scored,$level,$result,$duration"
} 
test_is_enabled() {
    id=$1
    level=$2
    service=$3
    name=$4
    description="Ensure $name service is enabled"
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $( systemctl is-enabled $service ) == "enabled" ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_is_installed() {
    id=$1
    level=$2
    pkg=$3
    name=$4
    description="Ensure $name is installed"
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}
test_is_not_installed() {
    id=$1
    level=$2
    pkg=$3
    name=$4
    description="Ensure $name is not installed"
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    [ $(rpm -q $pkg &>/dev/null; echo $?) -eq 0 ] || result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_perms() {
    id=$1
    level=$2
    perms=$3
    file=$4
    description="Ensure permissions on $file are configured"
    scored="Scored"
    test_start_time=$(test_start $id)
    
    ## Tests Start ##
    u=$(echo $perms | cut -c1)
    g=$(echo $perms | cut -c2)
    o=$(echo $perms | cut -c3 )
    file_perms="$(stat $file | awk '/Access: \(/ {print $2}')"
    file_u=$(echo $file_perms | cut -c3)
    file_g=$(echo $file_perms | cut -c4)
    file_o=$(echo $file_perms | cut -c5)
    
    [ "$(ls -ld $file | awk '{ print $3" "$4 }')" == "root root" ] || state=1
    [ $file_u -le $u ] || state=1
    [ $file_g -le $g ] || state=1
    [ $file_o -le $o ] || state=1
    
    [ $state -eq 0 ] && result=Pass
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


## Section 1 - Operating System Level Configuration
test_1.1() {
    id=$1
    level=$2
    description="Place Databases on Non-System Partitions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ ! $(mysql -u "$user" -e 'show variables where variable_name = "datadir";' \
          | grep datadir \
          | cut -f 2 \
          | xargs df -h \
          | grep /  \
          | cut -d ' ' -f1 \
          | xargs findmnt \
          | tail -1 \
          | cut -d ' ' -f1) =~ ^(/usr|/|/var)$ ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


test_1.2() {
    id=$1
    level=$2
    description="Use Dedicated Least Privileged Account for MySQL Daemon/Service"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(ps -ef | egrep "^mysql.*$" | wc -l) -gt 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_1.3() {
    id=$1
    level=$2
    description="Disable MySQL Command History"
    scored="Scored"
    test_start_time="$(test_start $id)"

    files= $(find /home -name ".mysql_history" 2> /dev/null);
    
    ## Tests Start ##
    [[ $($files | wc -l) -eq 0 ]] && state=1
    
    files | while read line; do
        [[ $(realpath $line) -ne "/dev/null" ]] && state=1
    done

    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_1.4() {
    id=$1
    level=$2
    description="Verify that the MYSQL_PWD Environment Variable is not in use"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    ## Using this test instead of the suggested test because the suggested test
    ## may return two results, which makes it hard to verify.
    [ -n "$MYSQL_PWD" ] && state=1 
    [ $state -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


test_1.5() {
    id=$1
    level=$2
    description="Disable Interactive Login"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(getent passwd mysql | egrep "^.*[\/bin\/false|\/sbin\/nologin]$" | wc -l) -ne 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_1.6() {
    id=$1
    level=$2
    description="Verify that 'MYSQYL_PWD' is not set in Users' profiles"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [ $(grep MYSQL_PWD /home/*/.{bashrc,profile,bash_profile} 2>/dev/null | wc -l) -eq 0 ] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

## Section 2 - Installation and Planning
test_2.6() {
    id=$1
    level=$2
    description="Set a Password Expiry Policy for specific users"
    scored="Not Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'select user, host, password_lifetime from mysql.user;' | grep NULL | wc -l) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
    
}

## Section 3 - File System Permissions
test_3.1() {
    id=$1
    level=$2
    description="Ensure 'datadir' has appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql kdfjd -e 'show variables where variable_name = "datadir";' \
        | grep datadir \
        | cut -f 2 \
        | xargs -I {} ls -l {}.. 2>/dev/null \
        | egrep "^d[r|w|x]{3}------\s*.\s*mysql\s*mysql\s*\d*.*mysql" \
        | wc -l) -ne 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.2() {
    id=$1
    level=$2
    description="Ensure 'log_bin_basename' files have appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    files="$(mysql -u "$user" -e 'show variables like "log_bin_basename";' \
         | grep "log_bin_basename" \
         | cut -f 2 \
         | xargs -I {} dirname {} \
         | xargs -I {} ls -l {}  2>/dev/null \
         | grep 'binlog.[0-9]')";
    count1="$(echo "${files}"| wc -l)";
    count2="$(echo "${files}" \
            | egrep  "^-[r|w]{2}-[r|w]{2}---\s*.\s*\s*\s*\d*.*" \
            | wc -l)";

    [[ count1 == count2 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.3() {
    id=$1
    level=$2
    description="Ensure 'log_error' has appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show global variables like "log_error";' \
        | grep "log_error" \
        | cut -f 2 \
        | xargs -I {} ls -l {} 2>/dev/null \
        | egrep "^-[r|w]{2}-[r|w]{2}----\s*.\s*mysql\s*mysql\s*\d*.*mysql" \
        | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.4() {
    id=$1
    level=$2
    description="Ensure 'slow_query_log' has appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    ## This test can fail if the file is not present.
    [[ $(mysql -u "$user" -e 'show variables like "slow_query_log_file";' \
        | grep "slow_query_log_file" \
        | cut -f 2 \
        | xargs -I {} ls -l {} 2> /dev/null \
        | egrep "^-[r|w]{2}-[r|w]{2}----\s*.\s*mysql\s*mysql\s*\d*.*mysql" \
        | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.5() {
    id=$1
    level=$2
    description="Ensure 'relay_log_basename' files have appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    ## Unsure what the format of relay logs look like... assuming it's the same
    ## as log_bin
    files="$(mysql -u "$user" -e 'show variables like "relay_log_basename";' \
         | grep "relay_log_basename" \
         | cut -f 2 \
         | xargs -I {} dirname {} \
         | xargs -I {} ls -l {} 2>/dev/null \
         | grep 'binlog.[0-9]')";
    count1="$(echo "${files}"| wc -l)";
    count2="$(echo "${files}" \
            | egrep  "^-[r|w]{2}-[r|w]{2}---\s*.\s*\s*\s*\d*.*" \
            | wc -l)";

    [[ count1 == count2 ]] && result="Pass"
    ## Tests End ##
    
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.6() {
    id=$1
    level=$2
    description="Ensure 'general_log_file' has appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show variables like "general_log_file";' \
        | grep "general_log_file" \
        | cut -f 2 \
        | xargs -I {} ls -l {} 2>/dev/null \
        | egrep "^-[r|w]{2}-[r|w]{2}----\s*.\s*mysql\s*mysql\s*\d*.*mysql" \
        | wc -l) -eq 1 ]] && result="Pass"      
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.7() {
    id=$1
    level=$2
    description="Ensure SSL key files have appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show variables where variable_name = "ssl_key";' \
        | grep datadir \
        | cut -f 2 \
        | xargs -I {} ls -l {} 2>/dev/null\
        | egrep "^-r--------[ \t]*.[ \t]*mysql[ \t]*mysql.*$" \
        | wc -l) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_3.8() {
    id=$1
    level=$2
    description="Ensure plugin directory has appropriate permissions"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show variables where variable_name = "plugin_dir";' \
       | grep plugin_dir \
       | cut -f 2 \
       | xargs -I {} ls -l {}/.. 2> /dev/null \
       | egrep "^drwxr[-w]xr[-w]x[ \t]*[0-9][ \t]*mysql[\t]*mysql.*plugin.*$" \
       | wc -l) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

## Section 4 - General
test_4.2() {
    id=$1
    level=$2
    description="Ensure the 'test' database is not installed"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show databases like "test";' \
       | grep "test" \
       | wc -l) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.3() {
    id=$1
    level=$2
    description="Ensure 'allow-suspicious-udfs' is set to 'FALSE'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(/usr/sbin/mysqld --help --verbose \
       | grep "allow-suspicious-udfs" \
       | grep FALSE \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.4() {
    id=$1
    level=$2
    description="Ensure 'local_infile' is disabled"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show variables where variable_name = "local_infile";' \
       | grep "OFF" \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.5() {
    id=$1
    level=$2
    description="Ensure 'mysqld' is not started with '--skip-grant-tables"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(/usr/sbin/mysqld --help --verbose \
       | grep "skip-grant-tables" \
       | grep FALSE \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.6() {
    id=$1
    level=$2
    description="Ensure '--skip-symbolic-links' is enabled"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e 'show variables like "have_symlink";' \
       | grep "DISABLED" \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.7() {
    id=$1
    level=$2
    description="Ensure the 'daemon_memcached' plugin is disabled"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SELECT * FROM information_schema.plugins WHERE PLUGIN_NAME='daemon_memcached';" \
       | grep "daemon_memcached" \
       | wc -l) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


test_4.8() {
    id=$1
    level=$2
    description="Ensure 'secure_file_priv' is not empty"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SHOW GLOBAL VARIABLES WHERE Variable_name = 'secure_file_priv' AND Value<>'';" \
       | grep "secure_file_priv" \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_4.9() {
    id=$1
    level=$2
    description="Ensure 'sql_mode' contains 'STRICT_ALL_TABLES'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SHOW VARIABLES LIKE 'sql_mode';" \
       | grep "sql_mode" \
       | grep "STRICT_ALL_TABLES" \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

# Section 6 - Auditing and Logging
test_6.1() {
    id=$1
    level=$2
    description="Ensure 'log_error' is not empty"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ -n $(mysql -u "$user" -e "SHOW VARIABLES LIKE 'log_error';" \
       | grep "log_error" \
       | cut -f2) ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_6.2() {
    id=$1
    level=$2
    description="Ensure log files are stored on a non-system partition"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ ! $(mysql -u "$user" -e "SELECT @@global.log_bin_basename;" \
         | grep "/" \
         | xargs -I {} dirname {} \
         | xargs df -h \
         | grep /  \
         | cut -d ' ' -f1 \
         | xargs findmnt \
         | tail -1 \
         | cut -d ' ' -f1) =~ ^(/usr|/|/var)$  ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_6.3() {
    id=$1
    level=$2
    description="Ensure 'log_error_verbosity' is not set to '1'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    verbosity="$(mysql -u "$user" -e "SHOW GLOBAL VARIABLES LIKE 'log_error_verbosity';" \
                | grep "log_error_verbosity" \
                | cut -f2 )"; 
    [[ verbosity -eq 2 ]] && result="Pass"
    [[ verbosity -eq 3 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_6.5() {
    id=$1
    level=$2
    description="Ensure 'log-raw' is set to 'OFF'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(/usr/sbin/mysqld --help --verbose \
       | grep "log-raw" \
       | grep FALSE \
       | wc -l) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

## Section 7 - Authentication

test_7.1() {
    id=$1
    level=$2
    description="Ensure passwords are not stored in the global configuration"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    for cnf_file in ${cnf_files[@]};
    do
      [[ $(grep "password" cnf_file 2>/dev/null 0| wc -l) -eq 1 ]] && status=1
    done

   [[ status -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_7.2() {
    id=$1
    level=$2
    description="Ensure 'sql_mode' contains 'NO_AUTO_CREATE_USER'"
    scored="Scored"
    test_start_time="$(test_start $id)"

    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SELECT @@global.sql_mode;" | grep "NO_AUTO_CREATE_USER" | wc -l) -eq 0 ]] && status=1
    [[ $(mysql -u "$user" -e "SELECT @@session.sql_mode;" | grep "NO_AUTO_CREATE_USER" | wc -l) -eq 0 ]] && status=1
    [[ status -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_7.3() {
    id=$1
    level=$2
    description="Ensure passwords are set for all MySQL accounts"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SELECT User,host FROM mysql.user WHERE authentication_string='';" | \
         wc -l) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


test_7.4() {
    id=$1
    level=$2
    description="Ensure 'default_password_lifetime' is less than or equal to '90'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SHOW VARIABLES LIKE 'default_password_lifetime';" | \
         grep "default_password_lifetime" |\
         cut -f 2 ) -le 90 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_7.5() {
    id=$1
    level=$2
    description="Ensure password complexity is in place"
    scored="Scored"
    test_start_time="$(test_start $id)"

    complexity=$(mysql -u "$user" -e "SHOW VARIABLES LIKE 'validate_password%';")
    
    ## Tests Start ##
    [[ $(echo "$complexity" | grep "length" | cut -f2 ) -lt 14 ]] && status=1
    [[ $(echo "$complexity" | grep "number_count" | cut -f2 ) -lt 1 ]] && status=1
    [[ $(echo "$complexity" | grep "mixed_case_count" | cut -f2 ) -lt 1 ]] && status=1
    [[ $(echo "$complexity" | grep "special_char_count" | cut -f2 ) -lt 1 ]] && status=1
    [[ ! $(echo "$complexity" | grep "policy" | cut -f2 )  =~ ^(STRONG|MEDIUM)$ ]] && status=1
    [[ status -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}


test_7.6() {
    id=$1
    level=$2
    description="Ensure no users have wildcard hostnames"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SELECT user, host from mysql.user where host='%';" | \
         wc -l ) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_7.7() {
    id=$1
    level=$2
    description="Ensure no anonymous accounts exist"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SELECT user, host from mysql.user where user='';" \
        | wc -l ) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

## Section 8 - Network
test_8.1() {
    id=$1
    level=$2
    description="Ensure 'have_ssl' is set to 'YES'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SHOW variables WHERE variable_name = 'have_ssl';" \
        | grep "log_error" \
        | cut -f 2) -eq "YES" ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_8.2() {
    id=$1
    level=$2
    description="Ensure 'ssl_type' is set to 'ANY'/'X509'/'SPECIFIED' for all remote users"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    num_users=$(mysql -u "$user" -e "SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost');" | wc -l)
    num_valid=$(mysql -u "$user" -e "SELECT user, host, ssl_type FROM mysql.user WHERE NOT HOST IN ('::1', '127.0.0.1', 'localhost') AND SSL_TYPE IN ('ANY', 'X509', 'SPECIFIED');" | wc -l)
    [[ num_users -eq num_valid ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

## Section 9 - Replication
test_9.2() {
    id=$1
    level=$2
    description="Ensure 'MASTER_SSL_VERIFY_SERVER_CERT' is set to 'YES' or '1'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "select ssl_verify_server_cert from mysql.slave_master_info;" \
        | grep "ssl_verify_server_cert" \
        | cut -f 2) -eq 1 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_9.3() {
    id=$1
    level=$2
    description="Ensure 'master_info_repository' is set to 'TABLE'"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SHOW GLOBAL VARIABLES LIKE 'master_info_repository';" \
        | grep "master_info_repository" \
        | cut -f 2) -eq "TABLE" ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_9.4() {
    id=$1
    level=$2
    description="Ensure 'super_priv' is not set to 'Y' for replication users"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "select user, host from mysql.user where user='repl' and Super_priv = 'Y';" \
        | wc -l ) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

test_9.5() {
    id=$1
    level=$2
    description="Ensure no replication users have wildcard hostnames"
    scored="Scored"
    test_start_time="$(test_start $id)"
    
    ## Tests Start ##
    [[ $(mysql -u "$user" -e "SELECT user, host FROM mysql.user WHERE user='repl' AND host = '%';" \
        | wc -l ) -eq 0 ]] && result="Pass"
    ## Tests End ##
    
    duration="$(test_finish $id $test_start_time)ms"
    write_result "$id,$description,$scored,$level,$result,$duration"
}

### Main ###
## Main script execution starts here

## Parse arguments passed in to the script
parse_args $@

## Run setup function
echo "LOADING" > $tmp_file_base-stage
setup
progress & 

## Run Tests
## These tests could've been condensed using loops but I left it exploded for
## ease of understanding / updating in the future.

## Section 1 - Operating System Level Configuration
if [ $(is_test_included 1; echo $?) -eq 0 ]; then   write_cache "1, Operating System Level Configuration"
    run_test 1.1 1 test_1.1
    run_test 1.2 1 test_1.2
    run_test 1.3 2 test_1.3
    run_test 1.4 1 test_1.4
    run_test 1.5 2 test_1.5
    run_test 1.6 1 test_1.6
fi

## Section 2 - Installation and Planning
if [ $(is_test_included 2; echo $?) -eq 0 ]; then   write_cache "2, Installation and Planning"
    if [ $(is_test_included 2.1; echo $?) -eq 0 ]; then   write_cache "2.1, Backup and Disaster Recovery"
        run_test 2.1.1 1 skip_test "Backup policy in place"
        run_test 2.1.2 1 skip_test "Verify backups are good"
        run_test 2.1.3 1 skip_test "Secure backup credentials"
        run_test 2.1.4 1 skip_test "The backups should be properly secured"
        run_test 2.1.5 2 skip_test "Point in time recovery"
        run_test 2.1.6 1 skip_test "Disaster recovery plan"
        run_test 2.1.7 1 skip_test "Backup of configuration and related files"
    fi
    run_test 2.2 1 skip_test "Dedicate Machine Running MySQL"
    run_test 2.3 1 skip_test "Do not specify passwords in command line"
    run_test 2.4 1 skip_test "Do not reuse usernames"
    run_test 2.5 2 skip_test "Do not use default or non-MySQL-specific cryptographic keys"
    run_test 2.6 1 test_2.6
fi

## Section 3 - File System Permissions
if [ $(is_test_included 3; echo $?) -eq 0 ]; then   write_cache "3, File System Permissions"
    run_test 3.1 1 test_3.1
    run_test 3.2 1 test_3.2
    run_test 3.3 1 test_3.3
    run_test 3.4 1 test_3.4
    run_test 3.5 1 test_3.5
    run_test 3.6 1 test_3.6
    run_test 3.7 1 test_3.7
    run_test 3.8 1 test_3.8
fi

## Section 4 - General
if [ $(is_test_included 4; echo $?) -eq 0 ]; then   write_cache "4, General"
    run_test 4.1 1 skip_test "Ensure latest security patches are applied"
    run_test 4.2 1 test_4.2
    run_test 4.3 2 test_4.3
    run_test 4.4 1 test_4.4
    run_test 4.5 1 test_4.5
    run_test 4.6 1 test_4.6
    run_test 4.7 1 test_4.7
    run_test 4.8 1 test_4.8
    run_test 4.9 2 test_4.9
fi

## Section 5 - MySQL Permissions
if [ $(is_test_included 5; echo $?) -eq 0 ]; then   write_cache "5, MySQL Permissions"
    ## Skipping 5.1 because it requires manually checking the admin names
    run_test 5.1 1 skip_test "Ensure only administrative users have full database access"
    run_test 5.2 1 skip_test "Ensure 'file_priv' is not set to 'Y' for non-administrative users"
    run_test 5.3 2 skip_test "Ensure 'process_priv' is not set to 'Y' for non-administrative users"
    run_test 5.4 1 skip_test "Ensure 'super_priv' is not set to 'Y' for non-administrative users"
    run_test 5.5 1 skip_test "Ensure 'shutdown_priv' is not set to 'Y' for non-administrative users"
    run_test 5.6 1 skip_test "Ensure 'create_user_priv' is not set to 'Y' for non-administrative users"
    run_test 5.7 1 skip_test "Ensure 'grant_priv' is not set to 'Y' for non-administrative users"
    run_test 5.8 1 skip_test "Ensure 'repl_slave_priv' is not set to 'Y' for non-slave users"
    run_test 5.9 1 skip_test "Ensure DML/DDL grants are limited to specific databases and users"
fi

## Section 6 - Auditing and Logging
if [ $(is_test_included 6; echo $?) -eq 0 ]; then   write_cache "6, Auditing and Logging"
    run_test 6.1 1 test_6.1
    run_test 6.2 1 test_6.2
    run_test 6.3 2 test_6.3
    ## Skipping 6.4 because it requires external checking of third-party loggers
    run_test 6.4 2 skip_test "Ensure audit logging is enabled" 
    run_test 6.5 1 test_6.5
fi

## Section 7 - Authentication
if [ $(is_test_included 7; echo $?) -eq 0 ]; then   write_cache "7, Authentication"
    run_test 7.1 1 test_7.1
    run_test 7.2 1 test_7.2
    run_test 7.3 1 test_7.3
    run_test 7.4 1 test_7.4
    run_test 7.5 1 test_7.5
    run_test 7.6 1 test_7.6
    run_test 7.7 1 test_7.7
fi

## Section 8 - Network
if [ $(is_test_included 8; echo $?) -eq 0 ]; then   write_cache "8, Network"
    run_test 8.1 1 test_8.1
    run_test 8.2 1 test_8.2
fi

## Section 9 - Replication
if [ $(is_test_included 9; echo $?) -eq 0 ]; then   write_cache "9, Replication"
    ## Skipping 9.1 because it requires manually checking of VPN/SSL/TLS/SSH
    run_test 9.1 1 skip_test "Ensure replication traffic is secured"
    run_test 9.2 1 test_9.2
    run_test 9.3 2 test_9.3
    run_test 9.4 1 test_9.4
    run_test 9.5 1 test_9.5
fi


## Wait while all tests exit
echo "RUNNING" > $tmp_file_base-stage
wait
echo "FINISHED" > $tmp_file_base-stage
write_debug "All tests have completed"

## Output test results
outputter
tidy_up

write_debug "Exiting with code $exit_code"
exit $exit_code
