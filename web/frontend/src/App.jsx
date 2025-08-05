import logo from './logo.svg';
import React, {useState} from 'react';
import './App.css';

function App() {
  return (
    <>
      <Login />
    </>
  );
}

function Login() {
  return (
    <>
      <form name="loginForm" action="http://localhost:8000/login" method="post" id="loginform">
        <input type="text" name="username" placeholder="Username..." />
        <input type="password" name="password" placeholder="Password..." />
        <button type="submit">Login</button>
      </form>
    </>
  );
}

export default App;
