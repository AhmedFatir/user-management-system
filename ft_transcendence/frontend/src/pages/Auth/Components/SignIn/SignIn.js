import React, { useState, useContext, useEffect } from 'react'
import './SignIn.css'
import Icon from '../../../../assets/Icon/icons'
import { assets } from '../../../../assets/assets'
import AuthContext from '../../../../context/Auth/AuthProvider'
import axios from '../../../../api/axios'
import { useLocation, useNavigate } from 'react-router-dom';
import useAuth from '../../../../hooks/useAuth'
import { fetchData } from '../../../Setting/components/TwoFaModal/TwoFaModal'
import useRefresh from '../../../../hooks/useRefresh'
import { useTranslation } from 'react-i18next';
import { ErrorToast } from '../../../../components/ReactToastify/ErrorToast'



const SIGNIN_URL = "/auth/token/"
const CALLBACK_URL = process.env.REACT_APP_CALLBACK_URL;
const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const SignIn = (props) => {
    const [isHidden, setIsHidden] = useState('hide_pass')
    const [errorMsg, setErrorMsg] = useState("")
    const {auth, setAuth} = useAuth()
    const navigate = useNavigate();
    const location = useLocation()
    const { t } = useTranslation();


    // const refresh = useRefresh()
    // const [isLoading, setIsLoading] = useState(true)

    
    // useEffect(() => {
    //     const checkToken = async () => {
    //       try {
    //         await refresh()
    //       } catch (e) {
    //         console.log(e)
    //       } finally {
    //         setIsLoading(false)
    //       }
    //     }
    //     if(!auth?.accessToken) {
    //       checkToken()
    //     }
    //   }, [])


    const [signInValues, setSignInValues] = useState({
        username: "",
        password: ""
    })

    function handleSignUpClick() {
        props.setIsLogin(false)
      }
    function handle42Click() {
        // navigate('/api_42')
        window.location.href = CALLBACK_URL;
    }

    const handleSignInSubmit = async (e) => {
        e.preventDefault();
        
        const formData = new FormData();
        formData.append('username', signInValues.username);
        formData.append('password', signInValues.password);
        // console.log(formData)
        try {
            const response = await axios.post(SIGNIN_URL, formData, {
                headers: { 'Content-Type': 'multipart/form-data' },
                withCredentials: true
            });
            const accessToken = response?.data?.access;
            // props.setAuth({username:signInValues.username, accessToken: accessToken})
            console.log('daaataaaa', response.data)
            if(response.data['2fa_required'] === true) {
                props.setAccessToken(accessToken)
                console.log('2FA enabled ya kho');
                props.setIsTwoFa(true)
                props.setTwoFaUser(response.data.username)
            }
            else {
                props.setAuth({username:signInValues.username, accessToken: accessToken})
                navigate('/');
            }
            // try {
            //     const userData = await fetchData(`${BACKEND_URL}/user/stats/`, accessToken);
            //     if(userData.is_2fa_enabled) {
            //         console.log('2FA enabled ya kho');
            //         props.setIsTwoFa(true)
            //         props.setTwoFaUser(userData.username)
            //     } else {
            //         setAuth({username:signInValues.username, accessToken: accessToken})
            //         navigate('/');
            //     }
            // }
            // catch (error) {
            //     console.error('Error fetching user data:', error);
            // 
        } catch(err) {
            console.log(err.response.status)
            if(err.response.status === 401) {
                ErrorToast("Invalid username or password.")
            }
            else {
                ErrorToast("An error occurred. Please try again later.")
            }
            console.log(err)
        } finally {
            // console.log("yay")
        }   
    }
    function handleInputChange(e) {
        setSignInValues({ ...signInValues, [e.target.name]: e.target.value });
    }

    // if (auth?.accessToken) {
    //     console.log('i am here')
    //     navigate('/')
    //   }

  return (
    <div className='signin-container'>
        <div className='signin-header'>
            <h1>{t('Sign In')}</h1>
            <p>{t('Welcome back! Sign in to access your account and dive into the world of gaming excitement.')}</p>
        </div>
        <form onSubmit={handleSignInSubmit} >
            <div className='signin-input-section'>
                <div className='signin-input'>
                    <Icon name='at' className='signin-icon'/>
                    <input name='username' placeholder={t('Email')}  type='text' onChange={handleInputChange}/>
                </div>
                <div className='signin-password'>
                    <div className='signin-input'>
                        <Icon name='lock' className='signin-icon'/>
                        <input name='password' placeholder={t('Password')} type={isHidden === 'hide_pass' ? 'password' : 'text'} onChange={handleInputChange}/>
                    </div>
                    <div className='show_pass' onClick={() => {
                        if(isHidden === 'hide_pass')
                            setIsHidden('show_pass')
                        else
                            setIsHidden('hide_pass')
                    }}>
                        <Icon name={isHidden} className='signin-icon'/>
                    </div>
                </div>
            </div>
            <div className='signin-submit-section'>
                <button>{t('Sign In')}</button>
            </div>
        </form>

        <div className='signin-sep'>
            <div className='signin-sep-s'></div>
            <div>{t('Or')}</div>
            <div className='signin-sep-s'></div>
        </div>
        <div className='school_auth' onClick={handle42Click}>
            <img src={assets.SchoolIcon}/>
            <p>{t('Sign In With 42')}</p>
        </div>
        <div className='school_auth' onClick={handle42Click}>
            <img src={assets.google}/>
            <p>{t('Sign In With Google')}</p>
        </div>
        
        <div className='signin-text-bottom'>
            <p>{t('Don’t have an account ?')} <span onClick={handleSignUpClick}>Sign Up here</span></p>
        </div>
    </div>
  )
}

export default SignIn