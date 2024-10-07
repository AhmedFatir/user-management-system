import React, { useEffect, useState } from 'react'
import './SignUp.css'
import { assets, avatars } from '../../../../assets/assets'
import AuthInput from '../AuthInput/AuthInput';
import axios from '../../../../api/axios';
import { useTranslation } from 'react-i18next'
import { ErrorToast } from '../../../../components/ReactToastify/ErrorToast';


const SIGNUP_URL = '/auth/user/register/'

const SignUp = (props) => {
    const [activeAvatar, setActiveAvatar] = useState(0);
    const [avatarFile, setAvatarFile] = useState(null);
    const { t } = useTranslation();
    const [signUpValues, setSignUpValues] = useState({
        username: "",
        email: "",
        password: "",
        confirm_password: ""
    });

    const handleFileChange = (event) => {
        setAvatarFile(event.target.files[0]);
        setActiveAvatar(null); 
    };

    const handleAvatarSelection = (index) => {
        setActiveAvatar(index);
        setAvatarFile(null);
    };

    const handleInputChange = (e) => {

        setSignUpValues({ ...signUpValues, [e.target.name]: e.target.value });
        console.log(signUpValues)
    };

    const handleSignUpSubmit = async (e) => {
        e.preventDefault();
        const formData = new FormData();
        formData.append('username', signUpValues.username);
        formData.append('email', signUpValues.email);
        formData.append('password', signUpValues.password);
        formData.append('confirm_password', signUpValues.confirm_password);
        if (avatarFile) {
            formData.append('avatar', avatarFile);
        } else {
            formData.append('avatar_type', activeAvatar);
        }

        try {
            const response = await axios.post(SIGNUP_URL, formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
                withCredentials: true
            });
            console.log(response.data);
            props.setIsLogin(true);
        }  catch (err) {
            if (err.response && err.response.data) {
                const errors = Object.values(err.response.data);
                const message = errors.flat().join(' '); 
                ErrorToast(message);
            } else {
                ErrorToast("An unexpected error occurred.");
            }
            console.error(err);
        }
        
    };

    const errorMsg = [
        {
            id: 0,
            msg: t("Username cannot contain special characters or spaces."),
            pattern: "^[A-Za-z][A-Za-z0-9_]{7,29}$"
        },
        {
            id: 1,
            msg: t("Email address must follow the format user@example.com."),
            pattern: "^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        },
        {
            id: 2,
            msg: t("Password is too weak. Please choose a more complex password to ensure account security."),
            pattern: "^(?=.*[a-z])(?=.*[A-Z])(?=.*\d).{8,}$",
        },
        {
            id: 3,
            msg: t("Oops! Looks like your passwords don't match. Please try again."),
            pattern: signUpValues.password
        }
    ];

    return (
        <div className='signup-container'>
            <h1>{t('Create Accoun')}t</h1>
            <div className='signup-avatar-section'>
                <h3>{t('Avatar')}</h3>
                <div className='signup-avatar-list'>
                    {avatars.map((avatar, index) => (
                        <img
                            key={index}
                            src={avatar.img}
                            className={activeAvatar === index ? 'active-avatar' : ''}
                            onClick={() => handleAvatarSelection(index)}
                        />
                    ))}
                    <label>
                        <input
                            type="file"
                            name="avatar"
                            id='uploadBtn'
                            className='upload-input'
                            onChange={handleFileChange}
                            accept="image/*"
                        />
                        <label htmlFor="uploadBtn">
                            <img src={assets.addAvatar} alt="Upload Avatar" />
                        </label>
                    </label>
                </div>
                <form className='signup-input-section' onSubmit={handleSignUpSubmit}>
                    <AuthInput name="username" placeholder={t('User Name')} type="text" value={signUpValues.username} onChange={handleInputChange} errorMessage={errorMsg[0].msg} pattern={errorMsg[0].pattern} />
                    <AuthInput name="email" placeholder={t('Email')} type="email" value={signUpValues.email} onChange={handleInputChange} errorMessage={errorMsg[1].msg} pattern={errorMsg[1].pattern} />
                    <AuthInput name="password" placeholder={t('Password')} type="password" value={signUpValues.password} onChange={handleInputChange} errorMessage={errorMsg[2].msg} pattern={errorMsg[2].pattern} />
                    <AuthInput name="confirm_password" placeholder={t('Confirm Password')} type="password" value={signUpValues.confirm_password} onChange={handleInputChange} errorMessage={errorMsg[3].msg} pattern={errorMsg[3].pattern} />
                    <button className="signup-switch" type="submit">{t('Create Account')}</button>
                    <button className="signup-switch" type="button" onClick={props.setIsLogin}>{t('Sign In')}</button>
                </form>
            </div>
        </div>
    );
};

export default SignUp;
