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
      <form name="loginForm" action="https://kxhmqxrn-8000.use.devtunnels.ms/login" method="post" id="loginform">
        <input type="text" name="username" placeholder="Username..." />
        <input type="password" name="password" placeholder="Password..." />
        <button type="submit">Login</button>
      </form>
    </>
  );
}

export default App;
