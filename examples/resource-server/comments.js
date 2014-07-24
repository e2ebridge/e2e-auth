/**
 * Copyright: E2E Technologies Ltd
 * Author: Cyril Schmitt <cschmitt@e2ebridge.com>
 */
"use strict";

var fs = require('fs');

var comments = [];
var idCounter = 0;

function save() {
    fs.writeFileSync(__dirname + '/comments.json', JSON.stringify(comments, null, 4));
}

try{
    comments = JSON.parse(fs.readFileSync(__dirname + '/comments.json'));
    comments.forEach(function(comment){
        if(+comment.id > idCounter){
            idCounter = +comment.id;
        }
    });
}catch(ignore){}

save();

exports.getAll = function(){
    return comments;
};

exports.add = function(comment){
    comment.id = (idCounter++) + '';
    comments.push(comment);
    save();
};

exports.delete = function(id){
    comments = comments.filter(function(comment){
        return comment.id !== id;
    });
    save();
};