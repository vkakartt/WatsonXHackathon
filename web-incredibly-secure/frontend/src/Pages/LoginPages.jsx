import React, { useState, useEffect } from 'react'
import {useNavigate} from 'react-router'
import {fetchData} from '../App'

export function LoginPage() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const navigate = useNavigate();

      useEffect(() => {
            fetchData('/users', 'GET').then(() => {
              navigate("/");
            }).catch((e) => {
                return;
            });
        }, []);
    

    function attemptLogin() {
        if (!username || !password) {
            console.log("Must input username or password");
            return;
        }
        
        const body = {
            username,
            password
        }

        fetchData("/login", "POST", body).then( response => {
            navigate("/");
        }).catch((e) => {
            console.log("Error getting tasks: " + e.message);
        });
    }

    return (
        <div className="login-container">
            <input 
                type="text"
                value={username}
                onChange={e => {setUsername(e.target.value)}}
            />
            <input
                type="text"
                value={"*".repeat(password.length)}
                onChange={e => {
                    if (e.target.value.length > password.length) {
                        setPassword(password + e.target.value[e.target.value.length-1]);
                    } else if (e.target.value.length < password.length) {
                        setPassword(password.substring(0, e.target.value.length));
                    }
                }}
                onPaste={e => e.preventDefault()}
            />
            <button onClick={attemptLogin}>
                Login
            </button>
            <button onClick={() => {navigate("/create-user")}}>
                Create User
            </button>
        </div>
    );
}


export function CreateUserPage() {
    const [username, setUsername] = useState("");
    const [password, setPassword] = useState("");
    const [confirmPassword, setConfirmPassword] = useState("");
    const navigate = useNavigate();

    useEffect(() => {
        fetchData('/users', 'GET').then(() => {
            navigate("/");
        }).catch((e) => {
            return;
        });
    }, []);

    function attemptCreateUser() {
        if (!username || !password || !confirmPassword) {
            console.log("Must input username or password");
            return;
        }
        if (password !== confirmPassword) {
            console.log("Passwords must match");
            return;
        }
        
        const body = {
            username,
            password
        }

        fetchData("/users", "POST", body).then( response => {
            navigate("/login");
        }).catch((e) => {
            console.log("Error getting tasks: " + e.message);
        });
    }

    return (
        <>
        <div className="login-container">
            <input 
                type="text"
                value={username}
                onChange={e => {setUsername(e.target.value)}}
            />
            <input
                type="text"
                value={"*".repeat(password.length)}
                onChange={e => {
                    if (e.target.value.length > password.length) {
                        setPassword(password + e.target.value[e.target.value.length-1]);
                    } else if (e.target.value.length < password.length) {
                        setPassword(password.substring(0, e.target.value.length));
                    }
                }}
                onPaste={e => e.preventDefault()}
            />
            <input
                type="text"
                value={"*".repeat(confirmPassword.length)}
                onChange={e => {
                    if (e.target.value.length > confirmPassword.length) {
                        setConfirmPassword(confirmPassword + e.target.value[e.target.value.length-1]);
                    } else if (e.target.value.length < password.length) {
                        setConfirmPassword(confirmPassword.substring(0, e.target.value.length));
                    }
                }}
                onPaste={e => e.preventDefault()}
            />
            <button onClick={attemptCreateUser}>
                Create User
            </button>
            <button onClick={() => {navigate("/login")}}>
                Login
            </button>
        </div>
        </>
    );
}