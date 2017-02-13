# zabbix_mysql
zabbix monitor plugin for mysql using python script</br>
##**OX00 安装**</br>
####安装python-mysql：</br>
pip install MySQL-python</br>
####安装脚本</br>
1.将script目录下zabbix_mysql放到一个制定目录下（自定义）</br>
2.将templates/userparameter_percona_mysql.conf 放到$zabbix_install_home/ect/zabbix_agentd.conf.d/目录下</br>
3.修改zabbix配置文件中添加include $zabbix_install_home/etc/zabbix_agentd.conf.d/*.conf</br>
4.重启zabbix-agent</br>
5.在zabbix的web界面中的configure栏目找到templates，点击templates 点击右上角的import，将templates目录下的zbx_percona_mysql_template.xml导入到模板里面</br>
##**OX01 notice**</br>
mysql的配置信息需要在脚本中修改</br>
如果开启缓存，缓存文件在mysql脚本中可修改，并且在创建缓存文件的时候修改缓存文件的other拥有写的权限
