import logo from './logo.svg';
import { Link, useRoutes, BrowserRouter as Router, useNavigate, useLocation } from 'react-router';
import { Outlet } from 'react-router-dom'
import React, { useEffect, useState, useRef } from 'react'
import {LoginPage, CreateUserPage} from './Pages/LoginPages'
import {ChatBot} from './Pages/ChatBotPage'
import {AboutPage, TypesVulnerabilitiesPage, FunctionalityPage} from './Pages/StaticPages'
import './App.css';

const BACKEND_ADDRESS = "http://localhost:8000";

function Routes() {
  const element = useRoutes([
    { path: "/login", element: <LoginPage />},
    { path: "/create-user", element: <CreateUserPage />},
    { 
      path: "/", 
      element: <Banner />,
      children: [
        { path: "chat", element: <ChatBot />},
        { path: "about", element: <AboutPage />},
        { path: "types-vulnerabilities", element: <TypesVulnerabilitiesPage />},
        { path: "functionality", element: <FunctionalityPage />},
        { path: "*", element: <NotFound />}
      ]
    }
  ]);

  return element;
}

function App() {
  return (
    <Router>
      <Routes />
    </Router>
  );
}

function Banner() {
  const navigate = useNavigate();
  const location = useLocation();
  const [username, setUsername] = useState('');
  const [showDropdown, setShowDropdown] = useState(false);
  const dropdownRef = useRef(null);
  
  const handleLogout = async () => {
    try {
      await fetchData('/logout', 'POST');
      navigate("/login");
    } catch (e) {
      console.log("Error: could not logout.");
    }
  }

  useEffect(() => {
    fetchData('/users', 'GET').then((response) => {
      setUsername(response.username);
      if (location.pathname === '/') {
        navigate("/chat");
      }
    }).catch((e) => {
      console.log(e)
      navigate("/login");
    });
    }, []);

  return (
    <>
      <div className="banner container">
        <img style={{marginRight:"7vw"}} src="https://www.transformatech.com/wp/wp-content/themes/infoway-transformatech/images/TransformaTech-Logo.jpg"/>
        <Link className="banner page-link" to="/chat">Chat Bot</Link>
        <Link className="banner page-link" to="/types-vulnerabilities">Types of Vulnerabilities</Link>
        <Link className="banner page-link" to="/functionality">Functionality</Link>
        <Link className="banner page-link" to="/about">About</Link>

        <div className="nav-right" ref={dropdownRef}>
          <button 
            onClick={() => setShowDropdown(!showDropdown)}
            className="user-button"
          >
            <div className="user-icon">👤</div>
            <span className="username">{username}</span>
            <div className={`dropdown-arrow ${showDropdown ? 'rotated' : ''}`}>▼</div>
          </button>
          
          {showDropdown && (
            <div className="user-dropdown">
              <div className="dropdown-item user-info">
                <div className="user-icon-large">👤</div>
                <div>
                  <div className="dropdown-username">{username}</div>
                  <div className="dropdown-email">Signed in</div>
                </div>
              </div>
              <div className="dropdown-divider"></div>
              <button onClick={handleLogout} className="dropdown-item logout-button">
                <span className="logout-icon">🚪</span>
                Sign Out
              </button>
            </div>
          )}
        </div>
      </div>
      <Outlet />
    </>
  );
}

export async function fetchData(path, method, body=null) {
    const requestOptions = {
    method,
    headers: { 'Content-Type': 'application/json' },
    credentials: "include"
  };

  // Only add body if it's not a GET or HEAD request
  if (body && method !== "GET" && method !== "HEAD") {
    requestOptions.body = JSON.stringify(body);
  }
  let toReturn;
  await fetch(BACKEND_ADDRESS + path, requestOptions)
    .then(response => {
      if (!response.ok) {
        return response.text().then(text => { throw new Error(text) })
      }

      const contentType = response.headers.get('content-type');
      if (contentType && contentType.includes('application/json')) {
        return response.json();
      } else {
        return response.text(); // Return as text if not JSON
      }
    })
    .then(data => toReturn = data)
    .catch(error => {
      console.error('Error fetching data: ', error.message);
      let toThrow;
      try {
        toThrow = new Error(JSON.parse(error.message).detail);
      } catch {
        throw error;
      }
      throw toThrow;
    });
    return toReturn;
}

function NotFound() {
  return (
    <>
    <div className="sub-container">
      <h2>404: Page Not Found.</h2>
    </div>
    </>
  )
}

export default App;
