import React, { useState, useRef, useEffect } from 'react';
import './Design.css';
import Icon from '../../assets/Icon/icons';
import Lottie from 'lottie-react';
import verifAnimation from './verifyAnimation.json';
import check from './check.json';
import failed from './failed.json';
import useAuth from '../../hooks/useAuth';
import {QRCodeSVG} from 'qrcode.react';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


const Design = () => {
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [verificationStatus, setVerificationStatus] = useState('idle');
  const {auth} = useAuth();
  const inputRefs = useRef([]);

  useEffect(() => {
    inputRefs.current[0].focus();
  }, []);

  const veryfyOtp = async (otpCode) => {
    setVerificationStatus('loading');
    try {
      console.log('otpCode: ', otpCode);
      const response = await fetch(`${BACKEND_URL}/auth/enable2fa/`,{
        method: 'POST',
        headers:{
          'Content-Type': 'application/json',
          'Authorization': `Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ0b2tlbl90eXBlIjoiYWNjZXNzIiwiZXhwIjoxNzI1NDU2MzU4LCJpYXQiOjE3MjUzNDg3MTgsImp0aSI6IjU1MjZlN2I0YWI1YzRkNzM5MGQ3ZjkwYzdiODRmOWRmIiwidXNlcl9pZCI6MX0.URxru2D-xrfEy1KFtey13MznmCGrXZC8H9sI4LngExM`
        },
        body: JSON.stringify({otp: otpCode})
      });
      if(response.ok) {
        setVerificationStatus('success');
      } else {
        setVerificationStatus('failed');
      }
    } catch (error) {
      console.log('Error verifying OTP: ', error);
      setVerificationStatus('failed');
  }
  }

  const handleChange = (element, index) => {
    if (isNaN(element.value)) return false;

    const newOtp = [...otp.map((d, idx) => (idx === index ? element.value : d))];
    setOtp(newOtp);
    
    if (element.nextSibling) {
      element.nextSibling.focus();
    }
    setVerificationStatus('idle')
    
    if (newOtp.every(data => data !== '')) {
      // veryfyOtp(newOtp.join(''));
    }

  };

  const handleBackspace = (e, index) => {
    if (e.key === 'Backspace' && !otp[index] && index > 0) {
      inputRefs.current[index - 1].focus();
    }
  };

  const renderVerificationStatus = () => {
    if (verificationStatus === 'idle') {
      return  <div className="qrcodeContainer">
                  <img src="https://www.imgonline.com.ua/examples/qr-code.png" alt="QR Code for 2FA setup" />
              </div> ;
    }

    if(verificationStatus === 'loading') {
      return <Lottie animationData={verifAnimation} style={{ width: 400, height: 400 }} />;
    }

    if (verificationStatus === 'success') {
      return <Lottie animationData={check} style={{ width: 400 , height: 400 }} loop='false' />;
    }

    if (verificationStatus === 'failed') {
      return <Lottie animationData={failed} style={{ width: 400, height: 400 }} loop='false'/>;
    }
  }

  return (
    <div className="MyContainer">
      <div className="TwoFaModalContainer">
        <div className="TwoFaModalHead">
          <Icon name="TwoFaIcon" className="TwoFaIcon" />
          <h1>Set up two factor authentication (2FA)</h1>
          <p>To authorize, scan the QR code with any authentication app</p>
        </div>
        <div className="TwoFaBody">
          {renderVerificationStatus()}
        </div>
        <div className="TwoFaBottom">
          <div className='otp-card-input'>
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
                />
              );
            })}
          </div>
          <button 
            className="setup-button" 
            disabled={otp.some(digit => digit === '')}
          >
            Complete Setup
          </button>
        </div>
      </div>
    </div>
  );
};

export default Design;

