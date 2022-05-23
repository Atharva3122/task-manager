const express = require('express');
const app = express();
const cors = require('cors');

const{mongoose} = require('./db/mongoose')

const bodyParser = require('body-parser');

//Load in the mongoose models
const{ List } = require('./db/models/list.model');
const{ Task } = require('./db/models/task.model');
const{ User } = require('./db/models/user.model');

const jwt = require('jsonwebtoken');

/* MIDDLEWARE */

// Load Middleware
app.use(bodyParser.json());

//CORS Headers Middlewares
app.use(function(req, res, next) {
    res.header("Access-Control-Allow-Origin", "*"); // update to match the domain you will make the request from
    res.header("Access-Control-Allow-Methods", "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE")
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept, x-access-token, x-refresh-token, _id");
     
    res.header(
        'Access-Control-Expose-Headers',
        'x-access-token, x-refresh-token'
    );

    next();
 });


// check whether the req has a valid JWT access token
let authenticate = (req, res, next) => {
    let token = req.header('x-access-token');

    // verify the JWT
    jwt.verify(token, User.getJWTSecret(), (err, decoded) => {
        if(err) {
            //there was an error
            // jwt is invalid- do not authenticate
            res.status(401).send(err);
        } else {
            // jwt is valid
            req.user_id = decoded._id;
            next();
        }
    });
}

 //Verify Refresh Token middleware (verify the session)
let verifySession = (req,res,next) => {
    //grab the refresh token from the request header
    let refreshToken = req.header('x-refresh-token');

    //grab the _id from the request token
    let _id = req.header('_id');

    User.findByIdAndToken(_id, refreshToken).then((user) => {
        if(!user) {
            //user couldnt be found
            return Promise.reject({
                'error': 'User not found. Make sure that the refresh token and user id are correct'
            });
        }


        //if the code reaches here that means that the user was found
        // therefore the refresh token still exists in the db but we still have to check

        req.user_id = user._id;
        req.userObject = user;
        req.refreshToken = refreshToken;
        
        let isSessionValid = false;

        user.sessions.forEach((session) => {
            if (session.token === refreshToken) {
                // check if the session has expired
                if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
                    //refresh token has not expired
                    isSessionValid = true;
                }
            }
        });

        if (isSessionValid) {
            // the session is valid, can continue with the next
             next();
        } else {
           //the session is not valid
            return Promise.reject({
                'error': 'Refresh token has expired or the session is invalid'
            })
        }

    }).catch((e) => {
        res.status(401).send(e);
    })

}


 /*END Middleware */

app.use(cors());


/* Route Handlers*/

/* List Routes*/

/**
 * Get /lists
 * Purpose: get all lists
 */
app.get('/lists', authenticate, (req,res) => {
    //We want to return an array of all the lists in the database that belong to the authenticated user
    List.find({
        _userId: req.user_id
    }).then((lists) => {
        res.send(lists);
    }).catch((e) => {
        res.send(e);
    });
})
/**
 * post /list
 * Purpose: Create a list
 */
app.post('/lists',authenticate,(req,res) => {
    // We want to create a new list and return the new list document back to the user (which includes id)
    // The list information (fields) will be passed in via the JSON request body
    let title = req.body.title;

    let newList = new List({
        title,
        _userId: req.user_id
    });
    newList.save().then((listDoc) => {
        // the full list document is returned (incl. id)
        res.send(listDoc);
    })
});


/**
 * Patch/Lists/:id
 * purpose: update a specified list
 */
app.patch('/lists/:id', authenticate, (req, res) => {
    //We want to update the specified list (list document with the id in the url) with the new values specified in the JSON body of the request
    List.findOneAndUpdate({ _id: req.params.id, _userId: req.user_id }, {
        $set: req.body
    }).then(() => {
        res.send({'message' : 'updated successfully'});
    })
});

/**
 * Delete /lists/:id
 * purpose: delete a list
 */
app.delete('/lists/:id', authenticate, (req, res) => {
    //We want to delete the specified list (document with id in the url)
    List.findOneAndRemove({
        _id: req.params.id,
        _userId: req.user_id
    }).then((removedListDoc) => {
        res.send(removedListDoc);
    

    //delete all the tasks in that list
    deleteTasksFromList(removedListDoc._id);
    })
});

/**
 * GET /lists/:listId/tasks
 * Purpose: Get all tasks in a specific list
 */

app.get('/lists/:listId/tasks', authenticate, (req, res) => {
    // We want to return all tasks that belong to a specific list (specified by listId)
    Task.find({
        _listId: req.params.listId
    }).then((tasks) => {
        res.send(tasks);
    }) 
});


/**
 * Post /lists/:listsId/tasks
 * Purpose: create a new task in the specific list
 */
app.post('/lists/:listId/tasks', authenticate, (req, res) => {
    //We want to create a new task into the list specified by listId
   
    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list) => {
        if (list) {
            //list object with the specified conditions found
            // therefore the currently authenticated user can create new task
            return true;
        }
        return false;
    }).then((canCreateTask) => {
        if(canCreateTask) {
            let newTask = new Task ({
                title: req.body.title,
                _listId: req.params.listId
            });
            newTask.save().then((newTaskDoc) => {
                res.send(newTaskDoc);
            })
        } else {
            res.sendStatus(404);
        }
    })

})
/**
 * Patch /lists/:listId/tasks/:taskId
 * Purpose: Update an existing task
 */
app.patch('/lists/:listId/tasks/:taskId', authenticate, async (req, res) => {
    
    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list) => {
        if (list) {
            // list object with the specified conditions was found
            // therefore the currently authenticated user can make updates to tasks within this list
            return true;
        }

        // else - the list object is undefined
        return false;
    }).then((canUpdateTasks) => {
        if (canUpdateTasks) {
            // the currently authenticated user can update tasks
            Task.findOneAndUpdate({
                _id: req.params.taskId,
                _listId: req.params.listId
            }, {
                    $set: req.body
                }
            ).then(() => {
                res.send({ message: 'Updated successfully.' })
            })
        } else {
            res.sendStatus(404);
        }
    })
});


/**
 * Delete /lists/:listId/tasks/:taskId
 * Purpose: Delete an existing task
 */
app.delete('/lists/:listId/tasks/:taskId', authenticate, (req, res) => {
    List.findOne({
        _id: req.params.listId,
        _userId: req.user_id
    }).then((list) => {
        if (list) {
            // list object with the specified conditions was found
            // therefore the currently authenticated user can make updates to tasks within this list
            return true;
        }

        // else - the list object is undefined
        return false;
    }).then((canDeleteTasks) => {
        
        if(canDeleteTasks) {
            Task.findOneAndRemove({
                _id: req.params.taskId,
                _listId: req.params.listId
            }).then((removedTaskDoc) => {
                res.send(removedTaskDoc);
            })

        } else {
            res.sendStatus(404);
        }        
    });
    
});


/* USER ROUTES */
/**
 * Post /users
 * Purpose: Sign Up
 */
app.post('/users', (req,res) => {
    //User Sign Up

    let body = req.body;
    let newUser = new User(body);

    newUser.save().then(() => {
        return newUser.createSession();
    }).then((refreshToken) => {
        //Session created successfully- refreshtoken returned.
        // now we generate an access auth token for the user

        return newUser.generateAccessAuthToken().then((accessToken) => {
            // access auth token generated successfully, now we return an object comtaining the auth tokens
            return {accessToken, refreshToken}
        });
    }).then((authTokens) => {
        //now we construct and send the response to  the user with their auth tokens in the header and the user object in the body
        res
            .header('x-refresh-token', authTokens.refreshToken)
            .header('x-access-token', authTokens.accessToken)
            .send(newUser);
    }).catch ((e) => {
        res.status(400).send(e);
    })
})


/**
 * POST /users/login
 * Purpose: Login
 */
app.post('/users/login', (req,res) => {
    let email = req.body.email;
    let password = req.body.password;

    User.findByCredentials(email, password).then((user) => {
        return user.createSession().then((refreshToken) => {
            //Session created successfully - refresh token returned
            // now we generate an access with token for the user

            return user.generateAccessAuthToken().then((accessToken) => {
                //access auth token generated successfully, now we return an object containing the auth tokens
                return {accessToken, refreshToken}
            });
        }).then((authTokens) => {
            //now we construct and send the response to  the user with their auth tokens in the header and the user object in the body
             res
                .header('x-refresh-token', authTokens.refreshToken)
                .header('x-access-token', authTokens.accessToken)
                .send(user);
        })
    }).catch((e) => {
        res.status(400).send(e);
    });
})


/**
 * Get /users/me/access-token
 * Purpose: generates and returns an access token
 */
app.get('/users/me/access-token', verifySession, (req,res) => {
    // The user is authenticated and the user id and user object is available
    req.userObject.generateAccessAuthToken().then((accessToken) => {
        res.header('x-access-token', accessToken).send({ accessToken });
    }).catch((e) => {
        res.status(400).send(e);
    });

})

/* Helper method */
let deleteTasksFromList = (_listId) => {
    Task.deleteMany({
        _listId
    }).then(() => {
        console.log("Tasks from" + _listId + "were deleted!");
    })
}




app.listen(3000, () => {
    console.log("Server is listening");
})