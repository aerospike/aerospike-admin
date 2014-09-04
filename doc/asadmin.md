# Aerospike Admin
## Interface Definition
### Overview
- The user interface should be case consistent.
- Minimize/eliminate persisted asadmin state.
- Consistent ordering using the node _alias_

### Command Modifiers:
#### _with_
- The _with_ clause which will be followed by a list of space delimited 
  node.
    - example: =info with n1 n2 n3=
        - This would run with nodes n1, n2, and n3.
    - Numerical ranges could be specified as [1:3] which would be the range 1,2,3.

#### _like_
- the _like_ parameter that would only show results
  like a particular value.
    - Example: =show stat like migrate= could be used to show migration stats
    - Example: =show config like defrag migrate with node n1= could show all the
	       defrag and migrate configuration parameters on the nodes _aliased_
	       n1.

### Terminology
- _alias_: This is the name that asadmin will call a particular node.
    - How does it work?
        - It finds the shortest prefix for the FQDNs of the hosts.
        - If it is unable to retrieve the FQDN it uses the IP address instead.

### Node Interaction
#### _info_
##### Modifiers:
- _with_
##### Default
- Output Tables for info hosts, info service, info network, info namespace,
  and info xdr
##### _info namespace_
- Same as current except object counts are replicated counts not divided by
  replication factor.
##### _info network_
- _network_ - Show network information
##### _info service_
- equivalent to previous interface's info node
##### _info xdr_
- Same as current except always sorted by _alias_.

#### _clinfo/asinfo_
##### _Modifiers_
- _with_
##### _Default_
- Both functions will exist and behave as the command line tool. Support both
  names so that 2.0 and 3.0 can have identical source.

#### _show_
##### Modifiers
- _with_, _like_
##### Default
- Default behavior, show help.
##### _show statistics_
- _statistics/stat_ - Show statistics for all nodes in some sort of tabular
		      format, unlike info this shows all stats in sorted order.
                      To display each stat will be a row, each node a column.
                      All of the _show_ commands will probably be displayed in
                      this way.
    - _server_ - show statistics for server
    - _xdr_ - show statistics for xdr
    - _set_ - show statistics for set
##### _latency_
- _latency_ - Show aerospiike latency information sorted by _alias_.
##### _show config_
- _config_ - show all configuration parameters in some tabular format
    - _service_ - show service parameters
    - _network_ - show network parameters
    - _namespace_ - show namespace parameters
    - _xdr_ - show xdr parameters
    - _diff_ - show only the params that are not the same across the cluster.
        - May also be nice to be able to only compare a subset of the config, IE
          =show config xdr compare=
###### _Modifier_
- _diff_ - only show parameters that are different for the nodes selected.
    - IE =show config xdr compare= would only show paramters that are different.

#### _set_
- The purpose of set is to provide an easier interface to set dynamic
  options as well as allow tab completion for the various options.
##### Modifiers
- _with_
##### Default
- Show help
##### _set service_
- _service_ <config name> <value>
##### _set network.heartbeat_
- _networ.heartbeat_ <config name> <value>
##### _set network.info_
- _networ.info_ <config name> <value>
##### _set namespace_
- _namespace_ <namespace name> <config name> <value>
- _namespace_ <namespace name> <set name> <config name> <value>
##### _set_xdr_
- _xdr_ <config name> <value>

#### _exec_
##### Modifiers
- _with_
##### TBD
- Requires SSH
- Execute a shell command on node selection

#### _watch_
- Similar to current watch
- Default to display every 10 seconds and only if there are changes
- Would be nice to highlight changes (similar to watch -d)
- {,#} - if a number is not provided, watch will check for changes every
	      10 seconds otherwise every provided number seconds. This command
	      may be used to prefix any other command except _monitor_
	      command.
- IE =watch 2 info service with n1= may display info service with n1 every 2
  seconds
##### Modifiers
- Modifiers supported by watched command
##### Default
- Show help

## Developer Guide
Important files and structure:
1. /monitor.py <br>
   monitor.py is the entry point specifically the *precmd* performs a
   search and finds the actual command the user is requesting and executes.
   <br>
   For most updates this file will not need modified.
2. /lib/controller.py <br>
   The controller is where commands are defined. Each command has a
   *commandHelp* decorator that accepts a list of lines to be displayed when
   help on a command is requested.
   <br>
   Commands are organized into an heirarchy, and the entry point is the
   *RootController*. End points int he heirachy will be methods of a controller
   that are prefixed "do_", default controller behavior will be prefixed
   "_do_".
3. /lib/view.py <br>
   With a little exception, nothing prints unless it is defined in view.py.
   This is where the results are rendered to the user. Very likely if you are
   adding a feature you will need to add code here.
4. /lib/table.py <br>
   The table class handles presentation of info and show commands and may work
   for yours as well.
   In the table module, the Extractors class defines various numeric formaters
   for instance if you wanted to display uptime in hrs/days use timeExtractor.
   <br>
   Before adding rows to the table you need to define a list of column names,
   if a column is bing renamed, use a tuple of ('original_name', 'new_name')
   <br>
   A datasource is really a data transformation, if you want to use
   timeExtractor on a column then you would need to call *addDataSource* on a
   new column name and pass the extractor as the function to do the
   transformation, passing the function the old columnname.

   Afterwards will need to add data to the table one row at a time.
5. /lib/cluster.py <br>
   Calls node methods in parallel, shouldn't need to modify for anything other
   than bug fixes.

6. /lib/node.py <br>
   For most commands this shouldn't need updated, but if the command requires
   a new type of info request then you will need to add the appropriate
   *info* or *xdr* method. These methods called by the cluster class, typically
   in parallel with other nodes.
