import React, { useEffect, useRef, useState } from 'react'
import './TwoFa.css'
import MainButton from '../../../../components/MainButton/MainButton'
import useAuth from '../../../../hooks/useAuth';
import { useNavigate } from 'react-router-dom';


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const TwoFa = (props) => {
    const [otp, setOtp] = useState(['', '', '', '', '', '']);
    const inputRefs = useRef([]);
    const {auth,setAuth} = useAuth();
    const [verificationStatus, setVerificationStatus] = useState('idle');
    const navigate = useNavigate()

    const handleContinueClick = () => {
      console.log('Continue clicked', verificationStatus);
      if(verificationStatus === 'success') {
        setAuth({username:"belkala", accessToken: props.accessToken})
        navigate('/')
      }
      else {
        console.log('OTP verification failed');
        //here i have to implement a toad notifiction to show the user that the otp verification failed
      }
    }

    const veryfyOtp = async (otpCode) => {
        try {
            const response = await fetch(`${BACKEND_URL}/auth/enable2fa/`, {
                method: 'POST',
                headers: {
                  'Content-Type': 'application/json',
                  'Authorization': `Bearer ${props.accessToken}`
                },
                body: JSON.stringify({otp: otpCode}),
                credentials: 'include'
                
              });
              if (response.ok) {
                  console.log('OTP verified successfully');
                  console.log(response)
                  // console.log(response.data.username, response.data.access)
                  // props.setAuth({username:response.data.username, accessToken: response.data.access})
                  setVerificationStatus('success');
                  props.setOtpSuccess(true)
                  return true;
                }
                return false;
        } catch(error) {
            console.log('Error verifying OTP: ', error);
            return false;
        }
    }
    useEffect(() => {
        inputRefs.current[0].focus();
      }, []);

    const handleChange = (element, index) => {
        if (isNaN(element.value)) return false;
        const newOtp = [...otp.map((d, idx) => (idx === index ? element.value : d))];
        setOtp(newOtp);

        if (element.nextSibling) {
            element.nextSibling.focus();
          }
          if (newOtp.every(data => data !== '')) {
            const otpCode = newOtp.join('');
            const status = veryfyOtp(otpCode, props.accessToken);
            console.log('status: ', status)
            if(status === true) {
                // setVerificationStatus('success');
                console.log('2FA successful, navigate to home page')
                // navigate('/')
            }
          }

    }
    const handleBackspace = (e, index) => {
        if (e.key === 'Backspace' && !otp[index] && index > 0) {
          inputRefs.current[index - 1].focus();
        }
      };

  return (
    <div className='AuthTwoFaConatiner'>
        <div className='AuthTwoFaHeader'>
            <h1>Welcome back ! {props.username} </h1>
            <p>entre 6-digit code from your two factor authentication APP.</p>
        </div>
        <div className='AuthOtpCard'>
            {otp.map((data, index) => {
              return (
                <input
                  type="text"
                  maxLength="1"
                  key={index}
                  value={data}
                  onChange={e => handleChange(e.target, index)}
                  onKeyDown={e => handleBackspace(e, index)}
                  ref={input => inputRefs.current[index] = input}
                  style={verificationStatus === 'success' ? {outline: '2px solid green'} : {}}
                />
              );
            })}
        </div>
        <div className='AuthTwoFaAction'>
            <button className='AuthTwoFaButton' onClick={handleContinueClick}>Continue</button>
            <button className="AuthTwoFaBackButton" onClick={props.handleBackToLogin}>&larr; Back to login</button>

        </div>
    </div>
  )
}

export default TwoFa