import React, { useState, useEffect, useRef } from 'react';
import { BrowserRouter as Router, Routes, Route, useNavigate, Navigate } from 'react-router-dom';
import './App.css'

const BACKEND_ADDRESS = 'http://localhost:8000';

export async function fetchData(path, method, body = null) {
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
        toThrow = new Error(JSON.parse(error.message).message);
      } catch {
        throw error;
      }
      throw toThrow;
    });
  return toReturn;
}

function NotFound() {
  const navigate = useNavigate();

  useEffect(() => {
    fetchData("/users", "GET").then((response)=>{
      console.log("User is logged in.");  
    }).catch((e)=>{
      navigate("/login");
    });
  }, []);

  return (
    <>
      <h2>Error 404:</h2>
      <div>Page Not Found.</div>
    </>
  )
}

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-gray-100">
        <main className="container mx-auto px-4 py-8">
          <Routes>
            <Route path="/login" element={<Login />} />
            <Route path="/create-user" element={<CreateUser />} />
            <Route path="/todolist" element={<TodoList />} />
            <Route path="/" element={<Navigate to="/todolist" />} />
            <Route path="/page-not-found" element={<NotFound />} />
            <Route path="*" element={<Navigate to="/page-not-found" />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
}

function Login() {
  const [formData, setFormData] = useState({
    username: '',
    password: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await fetchData('/login', 'POST', formData);
      navigate('/todolist');
    } catch (err) {
      setError(err.message || 'Login failed');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData("/users", "GET").then((response)=>{
      navigate("/todolist")
    }).catch((e)=>{
      console.log("User is not loggged in.")
    });
  }, [])

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="max-w-md mx-auto bg-white rounded-lg shadow-md p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-gray-800">Login</h2>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <input
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            placeholder="Username..."
            required
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <div>
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            placeholder="Password..."
            required
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-blue-600 text-white py-2 px-4 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
        >
          {loading ? 'Logging in...' : 'Login'}
        </button>
      </form>
      
      <p className="mt-4 text-center text-gray-600">
        Don't have an account?{' '}
        <button
          onClick={() => navigate('/create-user')}
          className="text-blue-600 hover:underline"
        >
          Sign up here
        </button>
      </p>
    </div>
  );
}

function CreateUser() {
  const [formData, setFormData] = useState({
    username: '',
    password: '',
    confirmPassword: ''
  });
  const [error, setError] = useState('');
  const [loading, setLoading] = useState(false);
  const navigate = useNavigate();

  const handleSubmit = async (e) => {
    e.preventDefault();
    setError('');

    if (formData.password !== formData.confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    setLoading(true);

    try {
      const userData = {
        username: formData.username,
        password: formData.password
      };
      
      await fetchData('/users', 'POST', userData);
      navigate('/login');
    } catch (err) {
      setError(err.message || 'Failed to create user');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchData("/users", "GET").then((response)=>{
      navigate("/todolist")
    }).catch((e)=>{
      console.log("User is not loggged in.")
    });
  }, [])

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  return (
    <div className="max-w-md mx-auto bg-white rounded-lg shadow-md p-6">
      <h2 className="text-2xl font-bold mb-6 text-center text-gray-800">Create Account</h2>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
        </div>
      )}
      
      <form onSubmit={handleSubmit} className="space-y-4">
        <div>
          <input
            type="text"
            name="username"
            value={formData.username}
            onChange={handleChange}
            placeholder="Username..."
            required
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <div>
          <input
            type="password"
            name="password"
            value={formData.password}
            onChange={handleChange}
            placeholder="Password..."
            required
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <div>
          <input
            type="password"
            name="confirmPassword"
            value={formData.confirmPassword}
            onChange={handleChange}
            placeholder="Confirm Password..."
            required
            className="w-full px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
        </div>
        
        <button
          type="submit"
          disabled={loading}
          className="w-full bg-green-600 text-white py-2 px-4 rounded-md hover:bg-green-700 focus:outline-none focus:ring-2 focus:ring-green-500 disabled:opacity-50"
        >
          {loading ? 'Creating Account...' : 'Create Account'}
        </button>
      </form>
      
      <p className="mt-4 text-center text-gray-600">
        Already have an account?{' '}
        <button
          onClick={() => navigate('/login')}
          className="text-blue-600 hover:underline"
        >
          Login here
        </button>
      </p>
    </div>
  );
}

function TodoList() {
  const [tasks, setTasks] = useState([]);
  const [newTask, setNewTask] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [creating, setCreating] = useState(false);
  const navigate = useNavigate();
  const username = useRef(null);

  useEffect(() => {
    fetchData("/users", "GET").then((response)=>{
      username.current = response.username;
      fetchTasks();
    }).catch((e)=>{
      navigate("/login");
      return;
    });
  }, []);

  const fetchTasks = async () => {
    try {
      setLoading(true);
      const data = await fetchData(`/tasks`, 'GET');
      setTasks(data || []);
    } catch (err) {
      setError(err.message || 'Failed to fetch tasks');
    } finally {
      setLoading(false);
    }
  };

  const createTask = async (e) => {
    e.preventDefault();
    if (!newTask.trim()) return;

    setCreating(true);
    try {
      const taskData = {
        text: newTask.trim(),
        is_completed: false
      };
      
      await fetchData('/tasks', 'POST', taskData);
      setNewTask('');
      await fetchTasks(); // Refresh the task list
    } catch (err) {
      setError(err.message || 'Failed to create task');
    } finally {
      setCreating(false);
    }
  };

  const toggleTask = async (taskId, currentStatus) => {
    try {
      await fetchData(`/tasks`, 'POST', { is_completed: !currentStatus, id: taskId });
      await fetchTasks(); // Refresh the task list
    } catch (err) {
      setError(err.message || 'Failed to update task');
    }
  };

  const deleteTask = async (taskId) => {
    try {
      await fetchData(`/tasks/${taskId}`, 'DELETE');
      await fetchTasks(); // Refresh the task list
    } catch (err) {
      setError(err.message || 'Failed to delete task');
    }
  };

  if (loading) {
    return (
      <div className="text-center py-8">
        <div className="text-xl text-gray-600">Loading tasks...</div>
      </div>
    );
  }

  return (
    <div className="max-w-2xl mx-auto">
      <h2 className="text-3xl font-bold mb-6 text-center text-gray-800">My Todo List</h2>
      
      {error && (
        <div className="mb-4 p-3 bg-red-100 border border-red-400 text-red-700 rounded">
          {error}
          <button
            onClick={() => setError('')}
            className="float-right text-red-700 hover:text-red-900"
          >
            ×
          </button>
        </div>
      )}
      
      {/* Create new task form */}
      <div className="bg-white rounded-lg shadow-md p-6 mb-6">
        <form onSubmit={createTask} className="flex gap-2">
          <input
            type="text"
            value={newTask}
            onChange={(e) => setNewTask(e.target.value)}
            placeholder="Enter a new task..."
            className="flex-1 px-3 py-2 border border-gray-300 rounded-md focus:outline-none focus:ring-2 focus:ring-blue-500"
          />
          <button
            type="submit"
            disabled={creating || !newTask.trim()}
            className="bg-blue-600 text-white px-6 py-2 rounded-md hover:bg-blue-700 focus:outline-none focus:ring-2 focus:ring-blue-500 disabled:opacity-50"
          >
            {creating ? 'Adding...' : 'Add Task'}
          </button>
        </form>
      </div>
      
      {/* Task list */}
      <div className="bg-white rounded-lg shadow-md">
        {tasks.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            No tasks yet. Create your first task above!
          </div>
        ) : (
          <div className="divide-y divide-gray-200">
            {tasks.map((task) => (
              <div key={task.id} className="p-4 flex items-center justify-between">
                <div className="flex items-center space-x-3">
                  <input
                    type="checkbox"
                    checked={task.is_completed}
                    onChange={() => toggleTask(task.id, task.is_completed)}
                    className="h-5 w-5 text-blue-600 rounded focus:ring-blue-500"
                  />
                  <span
                    className={`text-lg ${
                      task.is_completed
                        ? 'line-through text-gray-500'
                        : 'text-gray-800'
                    }`}
                  >
                    {task.text}
                  </span>
                </div>
                <button
                  onClick={() => deleteTask(task.id)}
                  className="text-red-600 hover:text-red-800 font-medium"
                >
                  Delete
                </button>
              </div>
            ))}
          </div>
        )}
      </div>
      
      {tasks.length > 0 && (
        <div className="mt-4 text-center text-gray-600">
          Total: {tasks.length} tasks | 
          Completed: {tasks.filter(t => t.completed).length} | 
          Remaining: {tasks.filter(t => !t.completed).length}
        </div>
      )}
    </div>
  );
}

export default App;