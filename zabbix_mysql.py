#!/bin/bash env
#_*_coding:utf8_*_


import MySQLdb
import re
import sys
import json
import os
import datetime
import time
# ============================================================================
# CONFIGURATION
# ============================================================================
# Define MySQL connection constants in config.php.  Arguments explicitly passed
# in from Cacti will override these.  However, if you leave them blank in Cacti
# and set them here, you can make life easier.  Instead of defining parameters
# here, you can define them in another file named the same as this file, with a
# .cnf extension.
# ============================================================================
mysql_user = 'root'
mysql_pass = '123456'
mysql_host = '192.168.1.108'
mysql_port = 3306
mysql_socket = "/tmp.msyql.sock"
mysql_flags = 0;
mysql_ssl  = False  # Whether to use SSL to connect to MySQL.
mysql_ssl_key  = '/etc/pki/tls/certs/mysql/client-key.pem'
mysql_ssl_cert = '/etc/pki/tls/certs/mysql/client-cert.pem'
mysql_ssl_ca   = '/etc/pki/tls/certs/mysql/ca-cert.pem'
mysql_connection_timeout = 5

heartbeat = False       # Whether to use pt-heartbeat table for repl. delay calculation.
heartbeat_utc = False    # Whether pt-heartbeat is run with --utc option.
heartbeat_table = 'percona.heartbeat'	# db.tbl.
heartbeat_server_id = 0  # Server id to associate with a heartbeat. Leave 0 if no preference.

cache_dir  = '/tmp'  # If set, this uses caching to avoid multiple calls.
poll_time  = 300     # Adjust to match your polling interval.
timezone   = None    # If not set, uses the system default.  Example: "UTC"
chk_options =  {
   'innodb'  : True,    # Do you want to check InnoDB statistics?
   'master'  : True,    # Do you want to check binary logging?
   'slave'   : True,    # Do you want to check slave status?
   'procs'   : True,    # Do you want to check SHOW PROCESSLIST?
   'get_qrt' : True,    # Get query response times from Percona Server or MariaDB?
}

use_ss    = False # Whether to use the script server or not
debug     = False # Define whether you want debugging behavior.
debug_log = False # If $debug_log is a filename, it'll be used.

# ============================================================================
# You should not need to change anything below this line.
# ============================================================================
version = '1.1.7'


def ss_get_mysql_stats(*args, **kwargs):
    global debug, mysql_user, mysql_pass, cache_dir, poll_time, chk_options
    global mysql_port, mysql_socket, mysql_flags
    global mysql_ssl, mysql_ssl_key, mysql_ssl_cert, mysql_ssl_ca
    global mysql_connection_timeout
    global heartbeat, heartbeat_table, heartbeat_server_id, heartbeat_utc

    user= kwargs.get('user') if kwargs.has_key('user') else mysql_user
    passwd = kwargs.get('passwd') if kwargs.has_key('passwd') else mysql_pass
    host= kwargs.get('host') if kwargs.has_key('host') else mysql_host
    port = kwargs.get('port') if kwargs.has_key('port') else mysql_port
    socket = kwargs.get('socket') if kwargs.has_key('socket') else mysql_socket
    flags = kwargs.get('flags') if kwargs.has_key('flags') else mysql_flags
    connection_timeout = kwargs.get('connection-timeout') if kwargs.has_key('connection-timeout') else mysql_connection_timeout
    heartbeat_server_id = kwargs.get('heartbeat_server_id') if kwargs.has_key('heartbeat_server_id') else heartbeat_server_id

    sanitized_host= host.replace(":","/").replace("","_")
    cache_file = "/tmp/mysql_zabbix_monitor_cache"

    fp =None
    if cache_dir and not kwargs.has_key('nocache'):
        if not os.path.exists(cache_file):
            fp = open(cache_file,'wb',)
        else:
            cache_file_ctime = os.stat(cache_file).st_ctime
            current_time = time.time()
            if int(current_time - cache_file_ctime) < 300:
                fp = open(cache_file,'rb')
                output_dic = json.load(fp)
                return output_dic
            else:
                fp = open(cache_file,'wb')
    else:
        fp = None

    #connect to MySQL
    conn = MySQLdb.Connect(host=host,port=port,user=user,passwd=passwd,unix_socket=mysql_socket)
    cursor = conn.cursor()
    """
    //ssl 相关设定
    获取mysql版本信息
    """
    #设置变量
    status = {
        'relay_log_space'            : 0 ,
        'binary_log_space'           : 0,
        'current_transactions'       : 0,
        'locked_transactions'        : 0,
        'active_transactions'        : 0,
        'innodb_locked_tables'       : 0,
        'innodb_tables_in_use'       : 0,
        'innodb_lock_structs'        : 0,
        'innodb_lock_wait_secs'      : 0,
        'innodb_sem_waits'           : 0,
        'innodb_sem_wait_time_ms'    : 0,
        #
        'State_closing_tables'       : 0,
        'State_copying_to_tmp_table' : 0,
        'State_end'                  : 0,
        'State_freeing_items'        : 0,
        'State_init'                 : 0,
        'State_locked'               : 0,
        'State_login'                : 0,
        'State_preparing'            : 0,
        'State_reading_from_net'     : 0,
        'State_sending_data'         : 0,
        'State_sorting_result'       : 0,
        'State_statistics'           : 0,
        'State_updating'             : 0,
        'State_writing_to_net'       : 0,
        'State_none'                 : 0,
        'State_other'                : 0,
    }
    # Get SHOW STATUS and convert the name-value array into a simple
    # associative array.
    cursor.execute("SHOW /*!50002 GLOBAL */ STATUS")
    for item in cursor.fetchall():
        status[item[0]] = item[1]

    # Get SHOW VARIABLES and do the same thing, adding it to the $status array.
    cursor.execute('SHOW VARIABLES')
    for item in cursor.fetchall():
        status[item[0]] = item[1]


    # Get SHOW SLAVE STATUS, and add it to the $status array.
    """
    监控mysql主从状态
    """
    # if chk_options['slave']:
    #     result = cursor.execute("SHOW SLAVE STATUS NONBLOCKING")
    #     if not result:
    #         result = cursor.execute('SHOW SLAVE STATUS NONBLOCKING')
    #         if not result:
    #             result = cursor.execute('SHOW SLAVE STATUS')
    #     slave_status_rows_gotten = 0
    #     for item in cursor.fetchall():
    #         slave_status_rows_gotten += 1


    # Get SHOW MASTER STATUS, and add it to the $status array.
    if chk_options['master']:
        pass



    # Get SHOW PROCESSLIST and aggregate it by state, then add it to the array
    # too.
    #返回的不是字典，根据自己实际情况调整
    #Id User Host db   Command Time  State Info
    if chk_options['procs']:
        cursor.execute('SHOW PROCESSLIST')
        for item in cursor.fetchall():
            state = item[6] if item[6] else None



    # Get SHOW ENGINES to be able to determine whether InnoDB is present.
    # pass
    engines = {}
    cursor.execute("SHOW ENGINES")
    for item in cursor.fetchall():
        engines[item[0]] = item[1]



    # Get SHOW INNODB STATUS and extract the desired metrics from it, then add
    # pass
    if chk_options.get('innodb') and engines.has_key('InnoDB') and engines['InnoDB'] == 'DEFAULT':
        cursor.execute("SHOW /*!50000 ENGINE*/ INNODB STATUS")
        innodb_status_txt = cursor.fetchall()[0][2]
        result = get_innodb_array(innodb_status_txt,None)
        for item in result.keys():
            status[item] = result.get(item)


    # Make table_open_cache backwards-compatible (issue 63).
    if status.get('table_open_cache'):
        status['table_cache'] = status.get('table_open_cache')
    # Compute how much of the key buffer is used and unflushed (issue 127).
    status['Key_buf_bytes_used'] = big_sub(status['key_buffer_size'],
                                           big_multiply(status['Key_blocks_unused'],status['key_cache_block_size']))
    status['Key_buf_bytes_unflushed'] = big_multiply(status['Key_blocks_not_flushed'],
                                                     status['key_cache_block_size'])
    # $status['Key_buf_bytes_used']
    # = big_sub($status['key_buffer_size'],
    #            big_multiply($status['Key_blocks_unused'],
    # $status['key_cache_block_size']));
    # $status['Key_buf_bytes_unflushed']
    # = big_multiply($status['Key_blocks_not_flushed'],
    # $status['key_cache_block_size']);
    if status.has_key('unflushed_log') and status.get('unflushed_log'):
        status['unflushed_log'] = max(status['unflushed_log'],status['innodb_log_buffer_size'])

    # Define the variables to output.  I use shortened variable names so maybe

    keys = {
      'Key_read_requests'           :  'gg',
      'Key_reads'                   :  'gh',
      'Key_write_requests'          :  'gi',
      'Key_writes'                  :  'gj',
      'history_list'                :  'gk',
      'innodb_transactions'         :  'gl',
      'read_views'                  :  'gm',
      'current_transactions'        :  'gn',
      'locked_transactions'         :  'go',
      'active_transactions'         :  'gp',
      'pool_size'                   :  'gq',
      'free_pages'                  :  'gr',
      'database_pages'              :  'gs',
      'modified_pages'              :  'gt',
      'pages_read'                  :  'gu',
      'pages_created'               :  'gv',
      'pages_written'               :  'gw',
      'file_fsyncs'                 :  'gx',
      'file_reads'                  :  'gy',
      'file_writes'                 :  'gz',
      'log_writes'                  :  'hg',
      'pending_aio_log_ios'         :  'hh',
      'pending_aio_sync_ios'        :  'hi',
      'pending_buf_pool_flushes'    :  'hj',
      'pending_chkp_writes'         :  'hk',
      'pending_ibuf_aio_reads'      :  'hl',
      'pending_log_flushes'         :  'hm',
      'pending_log_writes'          :  'hn',
      'pending_normal_aio_reads'    :  'ho',
      'pending_normal_aio_writes'   :  'hp',
      'ibuf_inserts'                :  'hq',
      'ibuf_merged'                 :  'hr',
      'ibuf_merges'                 :  'hs',
      'spin_waits'                  :  'ht',
      'spin_rounds'                 :  'hu',
      'os_waits'                    :  'hv',
      'rows_inserted'               :  'hw',
      'rows_updated'                :  'hx',
      'rows_deleted'                :  'hy',
      'rows_read'                   :  'hz',
      'Table_locks_waited'          :  'ig',
      'Table_locks_immediate'       :  'ih',
      'Slow_queries'                :  'ii',
      'Open_files'                  :  'ij',
      'Open_tables'                 :  'ik',
      'Opened_tables'               :  'il',
      'innodb_open_files'           :  'im',
      'open_files_limit'            :  'in',
      'table_cache'                 :  'io',
      'Aborted_clients'             :  'ip',
      'Aborted_connects'            :  'iq',
      'Max_used_connections'        :  'ir',
      'Slow_launch_threads'         :  'is',
      'Threads_cached'              :  'it',
      'Threads_connected'           :  'iu',
      'Threads_created'             :  'iv',
      'Threads_running'             :  'iw',
      'max_connections'             :  'ix',
      'thread_cache_size'           :  'iy',
      'Connections'                 :  'iz',
      'slave_running'               :  'jg',
      'slave_stopped'               :  'jh',
      'Slave_retried_transactions'  :  'ji',
      'slave_lag'                   :  'jj',
      'Slave_open_temp_tables'      :  'jk',
      'Qcache_free_blocks'          :  'jl',
      'Qcache_free_memory'          :  'jm',
      'Qcache_hits'                 :  'jn',
      'Qcache_inserts'              :  'jo',
      'Qcache_lowmem_prunes'        :  'jp',
      'Qcache_not_cached'           :  'jq',
      'Qcache_queries_in_cache'     :  'jr',
      'Qcache_total_blocks'         :  'js',
      'query_cache_size'            :  'jt',
      'Questions'                   :  'ju',
      'Com_update'                  :  'jv',
      'Com_insert'                  :  'jw',
      'Com_select'                  :  'jx',
      'Com_delete'                  :  'jy',
      'Com_replace'                 :  'jz',
      'Com_load'                    :  'kg',
      'Com_update_multi'            :  'kh',
      'Com_insert_select'           :  'ki',
      'Com_delete_multi'            :  'kj',
      'Com_replace_select'          :  'kk',
      'Select_full_join'            :  'kl',
      'Select_full_range_join'      :  'km',
      'Select_range'                :  'kn',
      'Select_range_check'          :  'ko',
      'Select_scan'                 :  'kp',
      'Sort_merge_passes'           :  'kq',
      'Sort_range'                  :  'kr',
      'Sort_rows'                   :  'ks',
      'Sort_scan'                   :  'kt',
      'Created_tmp_tables'          :  'ku',
      'Created_tmp_disk_tables'     :  'kv',
      'Created_tmp_files'           :  'kw',
      'Bytes_sent'                  :  'kx',
      'Bytes_received'              :  'ky',
      'innodb_log_buffer_size'      :  'kz',
      'unflushed_log'               :  'lg',
      'log_bytes_flushed'           :  'lh',
      'log_bytes_written'           :  'li',
      'relay_log_space'             :  'lj',
      'binlog_cache_size'           :  'lk',
      'Binlog_cache_disk_use'       :  'll',
      'Binlog_cache_use'            :  'lm',
      'binary_log_space'            :  'ln',
      'innodb_locked_tables'        :  'lo',
      'innodb_lock_structs'         :  'lp',
      'State_closing_tables'        :  'lq',
      'State_copying_to_tmp_table'  :  'lr',
      'State_end'                   :  'ls',
      'State_freeing_items'         :  'lt',
      'State_init'                  :  'lu',
      'State_locked'                :  'lv',
      'State_login'                 :  'lw',
      'State_preparing'             :  'lx',
      'State_reading_from_net'      :  'ly',
      'State_sending_data'          :  'lz',
      'State_sorting_result'        :  'mg',
      'State_statistics'            :  'mh',
      'State_updating'              :  'mi',
      'State_writing_to_net'        :  'mj',
      'State_none'                  :  'mk',
      'State_other'                 :  'ml',
      'Handler_commit'              :  'mm',
      'Handler_delete'              :  'mn',
      'Handler_discover'            :  'mo',
      'Handler_prepare'             :  'mp',
      'Handler_read_first'          :  'mq',
      'Handler_read_key'            :  'mr',
      'Handler_read_next'           :  'ms',
      'Handler_read_prev'           :  'mt',
      'Handler_read_rnd'            :  'mu',
      'Handler_read_rnd_next'       :  'mv',
      'Handler_rollback'            :  'mw',
      'Handler_savepoint'           :  'mx',
      'Handler_savepoint_rollback'  :  'my',
      'Handler_update'              :  'mz',
      'Handler_write'               :  'ng',
      'innodb_tables_in_use'        :  'nh',
      'innodb_lock_wait_secs'       :  'ni',
      'hash_index_cells_total'      :  'nj',
      'hash_index_cells_used'       :  'nk',
      'total_mem_alloc'             :  'nl',
      'additional_pool_alloc'       :  'nm',
      'uncheckpointed_bytes'        :  'nn',
      'ibuf_used_cells'             :  'no',
      'ibuf_free_cells'             :  'np',
      'ibuf_cell_count'             :  'nq',
      'adaptive_hash_memory'        :  'nr',
      'page_hash_memory'            :  'ns',
      'dictionary_cache_memory'     :  'nt',
      'file_system_memory'          :  'nu',
      'lock_system_memory'          :  'nv',
      'recovery_system_memory'      :  'nw',
      'thread_hash_memory'          :  'nx',
      'innodb_sem_waits'            :  'ny',
      'innodb_sem_wait_time_ms'     :  'nz',
      'Key_buf_bytes_unflushed'     :  'og',
      'Key_buf_bytes_used'          :  'oh',
      'key_buffer_size'             :  'oi',
      'Innodb_row_lock_time'        :  'oj',
      'Innodb_row_lock_waits'       :  'ok',
      'Query_time_count_00'         :  'ol',
      'Query_time_count_01'         :  'om',
      'Query_time_count_02'         :  'on',
      'Query_time_count_03'         :  'oo',
      'Query_time_count_04'         :  'op',
      'Query_time_count_05'         :  'oq',
      'Query_time_count_06'         :  'or',
      'Query_time_count_07'         :  'os',
      'Query_time_count_08'         :  'ot',
      'Query_time_count_09'         :  'ou',
      'Query_time_count_10'         :  'ov',
      'Query_time_count_11'         :  'ow',
      'Query_time_count_12'         :  'ox',
      'Query_time_count_13'         :  'oy',
      'Query_time_total_00'         :  'oz',
      'Query_time_total_01'         :  'pg',
      'Query_time_total_02'         :  'ph',
      'Query_time_total_03'         :  'pi',
      'Query_time_total_04'         :  'pj',
      'Query_time_total_05'         :  'pk',
      'Query_time_total_06'         :  'pl',
      'Query_time_total_07'         :  'pm',
      'Query_time_total_08'         :  'pn',
      'Query_time_total_09'         :  'po',
      'Query_time_total_10'         :  'pp',
      'Query_time_total_11'         :  'pq',
      'Query_time_total_12'         :  'pr',
      'Query_time_total_13'         :  'ps',
      'wsrep_replicated_bytes'      :  'pt',
      'wsrep_received_bytes'        :  'pu',
      'wsrep_replicated'            :  'pv',
      'wsrep_received'              :  'pw',
      'wsrep_local_cert_failures'   :  'px',
      'wsrep_local_bf_aborts'       :  'py',
      'wsrep_local_send_queue'      :  'pz',
      'wsrep_local_recv_queue'      :  'qg',
      'wsrep_cluster_size'          :  'qh',
      'wsrep_cert_deps_distance'    :  'qi',
      'wsrep_apply_window'          :  'qj',
      'wsrep_commit_window'         :  'qk',
      'wsrep_flow_control_paused'   :  'ql',
      'wsrep_flow_control_sent'     :  'qm',
      'wsrep_flow_control_recv'     :  'qn',
      'pool_reads'                  :  'qo',
      'pool_read_requests'          :  'qp',
    };
    # output = []
    # for key in keys.keys():
    #     val = str(status[key]) if status.has_key(key) else '-1'
    #     output.append("%s:%s" % (keys.get(key), val))


    output_dic = {}
    for key in keys.keys():
        val = str(status[key]) if status.has_key(key) else "-1"
        output_dic[keys.get(key)] = val

    if fp is not None:
        json.dump(output_dic,fp)
    return output_dic
    """
    write to log
    """

def big_multiply(left, right, force = None):
    left = float(left) if left is not None else 0
    right = float(right) if right is not None else 0
    if force == 'bc':
        return int(left-right)
    else:
        return int(left*right)

def big_sub(left, right, force = None):
    left = float(left) if left is not None else 0
    right = float(right) if right is not None else 0
    return int(left-right)

def big_add(left,right,force =None):
    left = float(left) if left is not None else 0
    right = float(right) if right is not None else 0
    if force == 'bc':
        return int(left+right)
    return int(left+right)



def get_innodb_array(text, mysql_version):
    mysql_version = 57000
    results  = {
      'spin_waits'  : [],
      'spin_rounds' : [],
      'os_waits'    : [],
      'pending_normal_aio_reads'  : -1,
      'pending_normal_aio_writes' : -1,
      'pending_ibuf_aio_reads'    : -1,
      'pending_aio_log_ios'       : -1,
      'pending_aio_sync_ios'      : -1,
      'pending_log_flushes'       : -1,
      'pending_buf_pool_flushes'  : -1,
      'file_reads'                : -1,
      'file_writes'               : -1,
      'file_fsyncs'               : -1,
      'ibuf_inserts'              : -1,
      'ibuf_merged'               : -1,
      'ibuf_merges'               : -1,
      'log_bytes_written'         : -1,
      'unflushed_log'             : -1,
      'log_bytes_flushed'         : -1,
      'pending_log_writes'        : -1,
      'pending_chkp_writes'       : -1,
      'log_writes'                : -1,
      'pool_size'                 : -1,
      'free_pages'                : -1,
      'database_pages'            : -1,
      'modified_pages'            : -1,
      'pages_read'                : -1,
      'pages_created'             : -1,
      'pages_written'             : -1,
      'queries_inside'            : -1,
      'queries_queued'            : -1,
      'read_views'                : -1,
      'rows_inserted'             : -1,
      'rows_updated'              : -1,
      'rows_deleted'              : -1,
      'rows_read'                 : -1,
      'innodb_transactions'       : -1,
      'unpurged_txns'             : -1,
      'history_list'              : -1,
      'current_transactions'      : -1,
      'hash_index_cells_total'    : -1,
      'hash_index_cells_used'     : -1,
      'total_mem_alloc'           : -1,
      'additional_pool_alloc'     : -1,
      'last_checkpoint'           : -1,
      'uncheckpointed_bytes'      : -1,
      'ibuf_used_cells'           : -1,
      'ibuf_free_cells'           : -1,
      'ibuf_cell_count'           : -1,
      'adaptive_hash_memory'      : -1,
      'page_hash_memory'          : -1,
      'dictionary_cache_memory'   : -1,
      'file_system_memory'        : -1,
      'lock_system_memory'        : -1,
      'recovery_system_memory'    : -1,
      'thread_hash_memory'        : -1,
      'innodb_sem_waits'          : -1,
      'innodb_sem_wait_time_ms'   : -1,
    };
    txn_seen = False
    for line in text.split('\n'):
        line = line.strip()
        row = re.split(' ',line)

        # SEMAPHORES
        if line.find('Mutex spin waits') == 0:
            #['Mutex', 'spin', 'waits', '90,', 'rounds', '2700,', 'OS', 'waits', '82']
            results['spin_waits'] = int(row[3].strip(','))
            results['spin_rounds'] = int(row[5].strip(','))
            results['os_waits'] = int(row[8].strip(','))
        elif line.find("RW-shared spins") == 0 and line.find(";") > 0:
            # RW-shared spins 3859028, OS waits 2100750; RW-excl spins 4641946, OS waits 1530310
            results['spin_waits'] = int(row[2].strip(','))
            results['spin_waits'] = int(row[8].strip(','))
            results['os_waits'] = int(row[5].strip(';'))
            results['os_waits'] = int(row[11].strip(';'))
        elif line.find("RW-shared spins") == 0:
            #['RW-shared', 'spins', '2826,', 'rounds', '84780,', 'OS', 'waits', '2814']
            results['spin_waits'] = int(row[2].strip(','))
            results['spin_rounds'] = int(row[4].strip(','))
            results['os_waits'] = int(row[7].strip(','))
        elif line.find("RW-shared spins") == 0 and line.find("RW-excl spins") < 0:
            #RW-shared spins 604733, rounds 8107431, OS waits 241268
            results['spin_waits'] = int(row[2].strip(','))
            results['spin_rounds'] = int(row[4].strip(';'))
            results['os_waits'] = int(row[7].strip(';'))
        elif line.find("RW-excl spins") == 0:
            #['RW-excl', 'spins', '2,', 'rounds', '2040,', 'OS', 'waits', '68']
            results['spin_waits'] = int(row[2].strip(','))
            results['spin_rounds'] = int(row[4].strip(','))
            results['os_waits'] = int(row[7].strip(','))
        elif line.find("seconds the semaphore:") > 0:
            # --Thread 907205 has waited at handler/ha_innodb.cc line 7156 for 1.00 seconds the semaphore:
            results['innodb_sem_waits'] = 1
            results['innodb_sem_wait_time_ms'] = int(row[9].strip(','))*100
        # TRANSACTIONS
        elif line.find("Trx id counter") == 0:
            if mysql_version < 50600:
                # For versions prior 5.6: two decimals or one hex
                # Trx id counter 0 1170664159
                # Trx id counter 861B144C
                results['innodb_transactions'] = max(int(row[3].strip(',')),int(row[4].strip(','))) if row[4] else int(row[3].strip(','),16)
            else:
                results['innodb_transactions'] = int(row[3].strip(','))
            txn_seen = True
        elif line.find("Purge done for trx") == 0:
            #['Purge', 'done', 'for', "trx's", 'n:o', '<', '214608', 'undo', 'n:o', '<', '0', 'state:', 'running', 'but','idle']
            if mysql_version < 506000:
                # For versions prior 5.6: two decimals or one hex
                # Purge done for trx's n:o < 0 1170663853 undo n:o < 0 0
                # Purge done for trx's n:o < 861B135D undo n:o < 0
                purged_to = int(row[6].strip(','),16) if row[7] == 'undo' else max(int(row[6].strip(','),16),int(row[6].strip(','),16))
            else:
                # For versions 5.6+ and MariaDB 10.x: one decimal
                # Purge done for trx's n:o < 2903354 undo n:o < 0 state: running but idle
                purged_to = int(row[6].strip(','),16)
            results['unpurged_txns'] = big_sub(results['innodb_transactions'],purged_to)
        elif txn_seen and line.find("---TRANSACTION") == 0:
            results['current_transactions'] = 1
            if line.find('ACTIVE') >= 0:
                results['active_transactions'] = 1
        elif txn_seen and line.find("------- TRX HAS BEEN") == 0:
            # ------- TRX HAS BEEN WAITING 32 SEC FOR THIS LOCK TO BE GRANTED:
            results['innodb_lock_wait_secs'] = int(row[5].strip((',')))
        elif line.find("read views open inside InnoDB") > 0:
            # 1 read views open inside InnoDB
            #['0', 'read', 'views', 'open', 'inside', 'InnoDB']
            results['read_views'] = int(row[0])
        elif line.find("mysql tables in use") == 0:
            # mysql tables in use 2, locked 2
            results['innodb_tables_in_user'] = int(row[4].strip(','))
            results['innodb_locked_tables'] = int(row[6].strip(','))
        elif txn_seen and line.find("lock struct(s)") > 0:
            # 23 lock struct(s), heap size 3024, undo log entries 27
            # LOCK WAIT 12 lock struct(s), heap size 3024, undo log entries 5
            # LOCK WAIT 2 lock struct(s), heap size 368
            if line.find("LOCK WAIT") == 0:
                results['innodb_lock_structs'] = int(row[2].strip(','))
                results['locked_transactions'] = 1
            else:
                results['innodb_lock_structs'] = int(row[0].strip(','))

        # FILE I/O
        elif line.find("OS file reads") > 0:
            #['1186', 'OS', 'file', 'reads,', '68341', 'OS', 'file', 'writes,', '33879', 'OS', 'fsyncs']
            results['file_reads'] = int(row[0])
            results['file_writes'] = int(row[4])
            results['file_fsyncs'] = int(row[8])
        elif line.find("Pending normal aio reads:") == 0:
            #['Pending', 'normal', 'aio', 'reads:', '0', '[0,', '0,', '0,', '0]', ',', 'aio', 'writes:', '0', '[0,', '0,', '0,', '0]', ',']
            results['pending_normal_aio_reads'] = int(row[4])
            results['pending_normal_aio_writes'] = int(row[12])
        elif line.find("ibuf aio reads") == 0:
            #['ibuf', 'aio', 'reads:', '0,', 'log', "i/o's:", '0,', 'sync', "i/o's:", '0']
            results['pending_ibuf_aio_reads'] = int(row[3].strip(','))
            results['pending_aio_log_ios'] = int(row[6].strip(','))
            results['pending_aio_sync_ios'] = int(row[9].strip(','))
        elif line.find("Pending flushes (fsync)") == 0:
            #['Pending', 'flushes', '(fsync)', 'log:', '0;', 'buffer', 'pool:', '0']
            results['pending_log_flushes'] = int(row[4].strip(';'))
            results['pending_buf_pool_flushes'] = int(row[7])
        elif line.find("Ibuf for space 0: size") >= 0:
            # Older InnoDB code seemed to be ready for an ibuf per tablespace.  It
            # had two lines in the output.  Newer has just one line, see below.
            # Ibuf for space 0: size 1, free list len 887, seg size 889, is not empty
            # Ibuf for space 0: size 1, free list len 887, seg size 889,
            results['ibuf_used_cells'] = int(row[5].strip(':').strip(','))
            results['ibuf_free_cells'] = int(row[9].strip(';').strip(','))
            results['ibuf_cell_count'] = int(row[12].strip(';').strip(','))
        elif line.find("Ibuf: size") == 0:
            #['Ibuf:', 'size', '1,', 'free', 'list', 'len', '0,', 'seg', 'size', '2,', '40', 'merges']
            results['ibuf_used_cells'] = int(row[2].strip(','))
            results['ibuf_free_cells'] = int(row[6].strip(','))
            results['ibuf_cell_count'] = int(row[9].strip(','))
            if line.find('merges') > 0:
                results['ibuf_merges'] = int(row[10].strip(','))
        # elif line.find("merged operations:") == 0 and line.find('delete mark') >= 0:
        #     pass
        elif line.find(', delete mark') >= 0 :
            #['insert', '44,', 'delete', 'mark', '0,', 'delete', '0']
            results['ibuf_inserts'] = int(row[1].strip(','))
            results['ibuf_merged'] = int(row[1].strip(',')) + int(row[4].strip(',')) + int(row[6].strip(','))

        elif line.find(" merged recs, ") > 0:
            # 19817685 inserts, 19817684 merged recs, 3552620 merges
            results['ibuf_inserts'] = int(row[0].strip(','))
            results['ibuf_merged'] = int(row[2].strip(','))
            results['ibuf_merges'] = int(row[5].strip(','))
        elif line.find('Hash table size') == 0:
            #['Hash', 'table', 'size', '276707,', 'node', 'heap', 'has', '33', 'buffer(s)']
            results['hash_index_cells_total'] = int(row[3].strip(','))
            results['hash_index_cells_used'] = int(row[7].strip(','))
        elif line.find(" log i/o's done, ")> 0:
            #['24255', 'log', "i/o's", 'done,', '0.83', 'log', "i/o's/second"]
            results['log_writes'] = int(row[0])
        elif line.find(" pending log writes, ") > 0:
            #['0', 'pending', 'log', 'writes,', '0', 'pending', 'chkp', 'writes']
            results['pending_log_writes'] = int(row[0])
            results['pending_chkp_writes'] = int(row[4])
        elif line.find("Log sequence number") == 0:
            # Log sequence number 13093949495856 //plugin
            # Log sequence number 125 3934414864 //normal
            #['Log', 'sequence', 'number', '25184569']
            if len(row) > 4:
                results['log_bytes_written'] = max(int(row[3]),int(row[4]))
            else:
                results['log_bytes_written'] = int(row[3])
        elif line.find("Log flushed up to") >= 0:
            #['Log', 'flushed', 'up', 'to', '', '', '25255663']
            # Log flushed up to   13093948219327
            # Log flushed up to   125 3934414864
            if len(row) > 8:
                results['log_bytes_flushed'] = max(int(row[6]),int(row[7]))
            else:
                results['log_bytes_flushed'] = int(row[6])
        elif line.find("Total memory allocated") >= 0 and line.find("in additional pool allocated") > 0:
            #['Total', 'memory', 'allocated', '137363456;', 'in', 'additional', 'pool', 'allocated', '0']
            results['total_mem_alloc'] = int(row[3].strip(';'))
            results['additional_pool_alloc'] = int(row[8])
        elif line.find("Adaptive hash index ") == 0:
            #Adaptive hash index 1538240664 	(186998824 + 1351241840)
            results['active_transactions'] = int(row[3])
        elif line.find("Page hash     ") >=0 :
            ##   Page hash           11688584
            #results['page_hash_memory'] = int(row[2])
            pass
        elif line.find("Dictionary cache") >= 0:
            #   Page hash           11688584
            #results['page_hash_memory'] = int(row[2])
            pass
        elif line.find("File system") >= 0:
            #   File system         313848 	(82672 + 231176)
            #results['file_system_memory'] = to_int(row[2])
            pass
        elif line.find("Lock system") >= 0:
            #   Lock system         29232616 	(29219368 + 13248)
            #results['lock_system_memory'] = int(row[2])
            pass
        elif line.find("Recovery system") >= 0:
            #   Recovery system     0 	(0 + 0)
            #results['recovery_system_memory'] = int(row[2]);
            pass
        elif line.find("Threads            ") >= 0:
            #   Threads             409336 	(406936 + 2400)
            #results['thread_hash_memory'] = int(row[1]);
            pass
        elif line.find("innodb_io_pattern   ") >= 0:
            #   innodb_io_pattern   0 	(0 + 0)
            #results['innodb_io_pattern_memory'] = int(row[1]);
            pass
        elif line.find("Buffer pool size ") >= 0:
            #['Buffer', 'pool', 'size', '', '', '8192']
            # The " " after size is necessary to avoid matching the wrong line:
            # Buffer pool size        1769471
            # Buffer pool size, bytes 28991012864
            results['pool_size'] = int(row[5])
        elif line.find("Database pages") >= 0:
            #['Database', 'pages', '', '', '', '', '994']
            results['database_pages'] = int(row[6])
        elif line.find("Modified db pages") >= 0:
            #['Modified', 'db', 'pages', '', '45']
            results['modified_pages'] = int(row[4])
        elif line.find("Pages read ahead") >= 0:
            #['Pages', 'read', 'ahead', '0.00/s,', 'evicted', 'without', 'access', '0.00/s,', 'Random', 'read', 'ahead', '0.00/s']
            ## Must do this BEFORE the next test, otherwise it'll get fooled by this
            # line from the new plugin (see samples/innodb-015.txt):
            # Pages read ahead 0.00/s, evicted without access 0.06/s
            # TODO: No-op for now, see issue 134.
            pass
        elif line.find("Pages read") == 0:
            #['Pages', 'read', '845,', 'created', '149,', 'written', '53991']
            results['pages_read'] = int(row[2].strip(','))
            results['pages_created'] = int(row[4].strip(','))
            results['pages_written'] = int(row[6].strip(','))
        elif line.find("Number of rows inserted") == 0:
            #['Number', 'of', 'rows', 'inserted', '16243,', 'updated', '7859,', 'deleted', '10849,', 'read', '1488153']
            results['rows_inserted'] = int(row[4].strip(','))
            results['rows_updated'] = int(row[6].strip(','))
            results['rows_deleted'] = int(row[8].strip(','))
            results['rows_read'] = int(row[10].strip(','))
        elif line.find(" queries inside InnoDB, ") >= 0:
            #['0', 'queries', 'inside', 'InnoDB,', '0', 'queries', 'in', 'queue']
            results['queries_inside'] = int(row[0])
            results['queries_queued'] = int(row[4])
    for key in ['spin_waits','spin_rounds','os_waits']:
        results[key] = int(results[key])
    return results


def main(*args,**kwargs):
    status_out = ss_get_mysql_stats()


    # for item in status:
    # #     print item
    result = status_out.get(sys.argv[1]) if status_out.has_key(sys.argv[1]) else '-1'
    print result


if __name__ == "__main__":
    main()