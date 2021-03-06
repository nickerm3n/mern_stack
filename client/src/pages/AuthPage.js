import React, { useState } from 'react';
import './AuthPage.css'
import { useHttp } from '../hooks/http.hook';

export const AuthPage = () => {
    const {loading, request} = useHttp()

    const [form, setForm] = useState({
        email: '', password: ''
    })

    const changeHandler = event => {
        setForm({ ...form, [event.target.name]: event.target.value })
    }

    const registerHandler = async () => {
        try {
            const data = await request('/api/auth/register', 'POST', {...form});
            console.log('Data', data)
        } catch(err) {

        }
    }

    return (
        <div className="row">
            <div className="col s6 offset-s3">
                <h1>Сократить Сыллку</h1>
                <div className="card blue darken-1">
                    <div className="card-content white-text">
                        <span className="card-title">Авторизация</span>
                        <div className="input-field ">
                            <input 
                              placeholder="Введите email" 
                              id="email" 
                              type="text" 
                              className="validate" 
                              name="email"
                              onChange={changeHandler} />
                            <label htmlFor="email">First Name</label>
                        </div>
                        <div className="input-field">
                            <input 
                              placeholder="Введите пароль" 
                              id="password" 
                              type="password" 
                              className="validate" 
                              name="password"
                              onChange={changeHandler} />
                            <label htmlFor="password">Last Name</label>
                        </div>
                    </div>
                    <div className="card-action">
                        <button className="btn yellow darken-4" disabled={loading}>Войти</button>
                        <button className="btn grey lighten-1 black-text" onClick={registerHandler} disabled={loading}>Регистрация</button>
                    </div>
                </div>
            </div>
        </div>
    )
}