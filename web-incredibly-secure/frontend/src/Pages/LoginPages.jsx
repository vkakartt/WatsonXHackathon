import React, { useState, useEffect } from 'react'
import {useNavigate} from 'react-router'
import {fetchData} from '../App'
import '../App.css'
import './Login.css'

export function LoginPage() {
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
        navigate('/chat');
        } catch (err) {
        setError(err.message || 'Login failed');
        } finally {
        setLoading(false);
        }
    };

    useEffect(() => {
        fetchData('/users', 'GET').then(() => {
            navigate("/");
        }).catch((e) => {
            return;
        });
    }, []);

    const handleChange = (e) => {
        setFormData({
        ...formData,
        [e.target.name]: e.target.value
        });
    };

    return (
        <div className="auth-container">
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
        </div>
    );
}

export function CreateUserPage() {
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
            fetchData("/users", "GET").then((response) => {
                navigate("/")
            }).catch((e) => {});
        }, [])

    const handleChange = (e) => {
        setFormData({
            ...formData,
            [e.target.name]: e.target.value
        });
    };

    return (
        <div className="auth-container">
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
        </div>
    );
}