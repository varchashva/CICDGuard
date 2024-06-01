;(function (undefined) {
    'use strict';

    if (typeof sigma === 'undefined')
        throw 'sigma is not declared';

    // Declare neo4j package
    sigma.utils.pkg("sigma.neo4j");

    // Initialize package:
    sigma.utils.pkg('sigma.utils');


    /**
     * This function is an helper for the neo4j communication.
     *
     * @param   {string|object}     neo4j       The URL of neo4j server or a neo4j server object.
     * @param   {string}            endpoint    Endpoint of the neo4j server
     * @param   {string}            method      The calling method for the endpoint : 'GET' or 'POST'
     * @param   {object|string}     data        Data that will be send to the server
     * @param   {function}          callback    The callback function
     */
    sigma.neo4j.send = function(neo4j, endpoint, method, data, callback) {
        var xhr = sigma.utils.xhr(),
            url, user, password;

        // if neo4j arg is not an object
        url = neo4j;
        if(typeof neo4j === 'object') {
            url = neo4j.url;
            user = neo4j.user;
            password = neo4j.password;
        }

        if (!xhr)
            throw 'XMLHttpRequest not supported, cannot load the file.';

        // Construct the endpoint url
        url += endpoint;

        xhr.open(method, url, true);
        if( user && password) {
            xhr.setRequestHeader('Authorization', 'Basic ' + btoa(user + ':' + password));
        }
        xhr.setRequestHeader('Accept', 'application/json');
        xhr.setRequestHeader('Content-type', 'application/json; charset=utf-8');
        xhr.onreadystatechange = function () {
            if (xhr.readyState === 4) {
                callback(JSON.parse(xhr.responseText));
            }
        };
        xhr.send(data);
    };

    /**
     * This function parse a neo4j cypher query result, and transform it into
     * a sigma graph object.
     *
     * @param  {object}     result      The server response of a cypher query.
     *
     * @return A graph object
     */
    sigma.neo4j.cypher_parse = function(result) {
        var graph = { nodes: [], edges: [] },
            nodesMap = {},
            edgesMap = {},
            key;

        // Iteration on all result data
        result.results[0].data.forEach(function (data) {
            // iteration on graph for all node
            data.graph.nodes.forEach(function (node) {
                var icons = {
                "runner": "\uf233",
                "workflow": "\uf0e8",
                "repo": "\uf09b",
                "job": "\uf0ae",
                "step": "\uf051",
                "command": "\uf121",
                "action": "\uf1fa",
                "organization": "\uf140",
                "jenkins": "\uf3b6",
                "bug": "\uf188"
                };

                var fa_icon_unicode = icons[node.labels[0].toLowerCase()];
                var icon_color = "#FFF";
                var nodecolor = "#3971ac"; 
                
                if (node.labels[0].toLowerCase().includes("jenkins")){
                    if (node.labels[0].toLowerCase().includes("jenkins_plugin")){
                        if (node.properties.enabled.toLowerCase().includes("false")){
                            nodecolor = "#777777";
                        }   
                        else{
                            nodecolor = "#48728B";
                        }                     
                    }    
                    else{
                            nodecolor = "#48728B";
                    } 
                }
                else if (node.labels[0].toLowerCase().includes("action")){
                    var nodecolor = "#4169E1";
                }
                else if (node.labels[0].toLowerCase().includes("github")){
                    var nodecolor = "#000000";
                }
                else if (node.labels[0].toLowerCase().includes("jfrog")){
                    if (node.labels[0].toLowerCase().includes("jfrog_user")){
                       if (node.properties.status.toLowerCase().includes("disabled")){
                            nodecolor = "#777777";
                        }
                        else{
                            nodecolor = "#18A558";
                        }     
                    }
                    else{
                        nodecolor = "#18A558";
                    }                    
                }
                else{
                    var nodecolor = "#808080";
                }

                var nodesize = 10;
                var nodemaxsize = 25;
                var nodeminsize = 10;
                var nodebordercolor = "#000000";
                var nodeborderwidth = 0;

                var label = node.labels[0].concat(node.properties)

                if (node.properties.affected_vulns.toLowerCase().includes("$")){
                    fa_icon_unicode = icons["bug"];
                    nodeminsize = 15;
                    nodesize = 15;
                    nodecolor = "#FF0000";
                    nodeborderwidth = 3;
                    // label = 
                }

                var sigmaNode =  {
                    id : node.id,
                    // label : node.labels[0],
                    x : Math.random(),// (node.properties.distance - 1) + radius * (Math.cos(angle * Math.PI / 180)) + stretch, //h+r*cos(a)
                    y : Math.random(),//radius * Math.sin(angle * Math.PI / 180), //k+r*sin(a), where k = 0
                    size: nodesize,
                    maxNodeSize: nodemaxsize,
                    minNodeSize: nodeminsize,
                    neo4j_labels : node.labels,
                    neo4j_data : node.properties,
                    borderColor: nodebordercolor,
                    color: nodecolor,
                    icon: {
                        font: 'FontAwesome',
                        content: fa_icon_unicode,
                        color: icon_color,
                        scale: 1.0
                    }, // icons might not be required other than for Bug node 
                    borderWidth: nodeborderwidth, //tester demand
                };
                if (sigmaNode.id in nodesMap) {
                    // do nothing
                } else {
                    nodesMap[sigmaNode.id] = sigmaNode;
                }
            });

            // iteration on graph for all node
            data.graph.relationships.forEach(function (edge) {
                var sigmaEdge =  {
                    id : edge.id,
                    // label : edge.type,
                    label: "label",
                    source : edge.startNode,
                    target : edge.endNode,
                    color : '#3971ac',
                    neo4j_type : edge.type,
                    neo4j_data : edge.properties,
                    type: 'curve', //this can be used to determine the type of connection
                    size: 15,
                };

                if (sigmaEdge.id in edgesMap) {
                    // do nothing
                } else {
                    edgesMap[sigmaEdge.id] = sigmaEdge;
                }
            });

        });

        // construct sigma nodes
        for (key in nodesMap) {
            graph.nodes.push(nodesMap[key]);
        }
        // construct sigma nodes
        for (key in edgesMap) {
            graph.edges.push(edgesMap[key]);
        }

        return graph;
    };


    /**
     * This function execute a cypher and create a new sigma instance or
     * updates the graph of a given instance. It is possible to give a callback
     * that will be executed at the end of the process.
     *
     * @param  {object|string}      neo4j       The URL of neo4j server or a neo4j server object.
     * @param  {string}             cypher      The cypher query
     * @param  {?object|?sigma}     sig         A sigma configuration object or a sigma instance.
     * @param  {?function}          callback    Eventually a callback to execute after
     *                                          having parsed the file. It will be called
     *                                          with the related sigma instance as
     *                                          parameter.
     */
    sigma.neo4j.cypher = function (neo4j, cypher, sig, callback) {
        var endpoint = '/db/data/transaction/commit',
            data, cypherCallback;

        // Data that will be send to the server
        data = JSON.stringify({
            "statements": [
                {
                    "statement": cypher,
                    "resultDataContents": ["graph"],
                    "includeStats": false
                }
            ]
        });

        // Callback method after server response
        cypherCallback = function (callback) {

            return function (response) {

                var graph = { nodes: [],
                              edges: [],

                             };

                graph = sigma.neo4j.cypher_parse(response);
                // Update the instance's graph:
                if (sig instanceof sigma) {
                    sig.graph.clear();
                    sig.graph.read(graph);

                    // ...or instantiate sigma if needed:
                } else if (typeof sig === 'object') {
                    sig = new sigma(sig);
                    sig.graph.read(graph);
                    sig.refresh();

                    // ...or it's finally the callback:
                } else if (typeof sig === 'function') {
                    callback = sig;
                    sig = null;
                }

                // Call the callback if specified:
                if (callback)
                    callback(sig || graph);
            };
        };

        // Let's call neo4j
        sigma.neo4j.send(neo4j, endpoint, 'POST', data, cypherCallback(callback));
    };

    /**
     * This function call neo4j to get all labels of the graph.
     *
     * @param  {string}       neo4j      The URL of neo4j server or an object with the url, user & password.
     * @param  {function}     callback   The callback function
     *
     * @return An array of label
     */
    sigma.neo4j.getLabels = function(neo4j, callback) {
        sigma.neo4j.send(neo4j, '/db/data/labels', 'GET', null, callback);
    };

    /**
     * This function parse a neo4j cypher query result.
     *
     * @param  {string}       neo4j      The URL of neo4j server or an object with the url, user & password.
     * @param  {function}     callback   The callback function
     *
     * @return An array of relationship type
     */
    sigma.neo4j.getTypes = function(neo4j, callback) {
        sigma.neo4j.send(neo4j, '/db/data/relationship/types', 'GET', null, callback);
    };

    sigma.neo4j.getNodes = function(neo4j, cypher, callback) {

        // Data that will be send to the server
       var data = JSON.stringify({
            "statements": [
                {
                    "statement": cypher,
                    "resultDataContents": ["graph"],
                    "includeStats": false
                }
            ]
        });

        sigma.neo4j.send(neo4j,'/db/data/transaction/commit' , 'POST', data, callback);
    };
}).call(this);

    
