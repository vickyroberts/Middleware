var express = require('express');
var jwt = require('jsonwebtoken');
var messages = require('../GlobalMessages.js');

exports.verifyTokenValidity=function(req, res, next){
  
    res.header('Access-Control-Allow-Credentials', true);
    res.header('Access-Control-Allow-Origin', req.headers.origin);
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE');
    res.header('Access-Control-Allow-Headers', 'X-Requested-With, X-HTTP-Method-Override, Content-Type, Accept');
 

   var token = req.body.token || req.headers['token-bind'];
   // var token = req.body.token;
    if(req.url != "/authuser" && req.url != "/putUserDetails" && req.method.toLowerCase() != "options")
    {
            // decode token
            if (token) {
                // verifies secret and checks exp
                jwt.verify(token, messages.tokenSec, function(err, decoded) {      
                if (err) {
                    return res.json({ success: false, message: messages.tokenInValid });    
                } else {
                    // if everything is good, save to request for use in other routes                    
                    if(decoded.uid == req.session.userid)
                    {
                        req.decoded = decoded;    
                        next();
                    }   
                    else
                    {
                        return res.json({ success: false, message: messages.tokenInValid });
                    }                 
                }
                });

            } else {
                // if there is no token
                // return an error
                return res.status(403).send({ 
                    success: false, 
                    message: messages.tokenNotAvailable 
                });            
            }
    }
    else
    {
            next();
    }
};