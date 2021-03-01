# Aerospike Admin
## Interface Definition
### Overview
- The user interface should be case consistent.
- Minimize/eliminate persisted asadmin state.
- Consistent ordering using the node **alias**

### Command Modifiers:
#### with
- The **with** clause which will be followed by a list of space delimited 
  node.
    - example: <code>info with n1 n2 n3</code>
        - This would run with nodes n1, n2, and n3.
    - Numerical ranges could be specified as [1:3] which would be the range 1,2,3.

#### like
- the **like** parameter that would only show results
  like a particular value.
    - Example: <code>show stat like migrate</code> could be used to show migration stats
    - Example: <code>show config like defrag migrate with node n1</code> could show all the
	       defrag and migrate configuration parameters on the nodes *aliased*
	       n1.

### Terminology
- **alias**: This is the name that asadmin will call a particular node.
    - How does it work?
        - It finds the shortest prefix for the FQDNs of the hosts.
        - If it is unable to retrieve the FQDN it uses the IP address instead.

### Node Interaction
#### info
##### Modifiers:
- with

##### Default
- Output Tables for info hosts, info service, info network, info namespace, and info xdr

##### info namespace
- Same as current except object counts are replicated counts not divided by replication factor.

##### info network
- **network** - Show network information

##### info service
- equivalent to previous interface's info node

##### info xdr
- Same as current except always sorted by **alias**.

#### asinfo
##### Modifiers
- with

##### Default
- Both functions will exist and behave as the command line tool. Support both names so that 2.0 and 3.0 can have identical source.

#### show
##### Modifiers
- with, like

##### Default
- Default behavior, show help.

##### show statistics
- **statistics** - Show statistics for all nodes in some sort of tabular
		 format, unlike info this shows all stats in sorted order.
                 To display each stat will be a row, each node a column.
                 All of the **show** commands will probably be displayed in
                 this way.
    - **server** - show statistics for server
    - **xdr** - show statistics for xdr
    - **set** - show statistics for set

##### latencies
- **latency** - Show Aerospike latency information sorted by **alias**.

##### show config
- **config** - show all configuration parameters in some tabular format
    - **service** - show service parameters
    - **network** - show network parameters
    - **namespace** - show namespace parameters
    - **xdr** - show xdr parameters
    - **diff** - show only the params that are not the same across the cluster.
        - May also be nice to be able to only compare a subset of the config.
        - IE <code>show config xdr compare</code>

###### Modifier
- **diff** - only show parameters that are different for the nodes selected.
    - IE =show config xdr compare= would only show parameters that are different.
#### watch
- Similar to current watch
- Default to display every 10 seconds and only if there are changes
- {,#} - if a number is not provided, watch will check for changes every
	      10 seconds otherwise every provided number seconds. This command
	      may be used to prefix any other command.
- IE <code>watch 2 info service with n1</code> may display info service with n1 every 2
  seconds

##### Modifiers
- Modifiers supported by watched command

##### Default
- Show help

## Developer Guide
Style Guide:
   To make things simple we are using "Black" a no hassle formatter https://black.readthedocs.io/en/stable/.
   Install it and you can either run Black manually on all files using `black test lib asadm.py` before
   committing or set it to format on save using your chosen code editor.


Important files and structure:

1. /asadmin.py

   asadmin.py is the entry point specifically the **precmd** performs a
   search and finds the actual command the user is requesting and executes.
   <br>
   For most updates this file will not need modified.

2. /lib/controller.py

   The controller is where commands are defined. Each command has a
   **commandHelp** decorator that accepts a list of lines to be displayed when
   help on a command is requested.
   <br>
   Commands are organized into an hierarchy, and the entry point is the
   **RootController**. End points in the hierarchy will be methods of a controller
   that are prefixed "do_", default controller behavior will be prefixed
   "\_do\_".

3. /lib/view/view.py

   With a little exception, nothing prints unless it is defined in view.py.
   This is where the results are rendered to the user. Very likely if you are
   adding a feature you will need to add code here.

4. /lib/view/table.py  Replaced by sheets.py

   The table class handles presentation of info and show commands and may work
   for yours as well.
   In the table module, the Extractors class defines various numeric formaters
   for instance if you wanted to display uptime in hrs/days use timeExtractor.

   Before adding rows to the table you need to define a list of column names,
   if a column is being renamed, use a tuple of ('original\_name', 'new\_name')

   A datasource is really a data transformation, if you want to use
   timeExtractor on a column then you would need to call **addDataSource** on a
   new column name and pass the extractor as the function to do the
   transformation, passing the function the old columnname.

5. /lib/view/sheets.py

   The sheet class was made as a retrospective replacement of table.py.  It was
   mostly developed by Kevin Porter.  Creating a table using sheets requires that
   you create a template defining how your table should appear, where it should
   extract (project) data from, if it should be converted, and if it should be 
   aggregated.  You can see all the created templates in /lib/view/templates.py

5. /lib/cluster.py

   Calls node methods in parallel, shouldn't need to modify for anything other
   than bug fixes.

6. /lib/node.py <br>
   For most commands this shouldn't need updated, but if the command requires
   a new type of info request then you will need to add the appropriate
   **info** or **xdr** method. These methods called by the cluster class, typically
   in parallel with other nodes.
