import React, { useState, useRef, useEffect, useContext } from 'react';
import './TwoFaModal.css';
import Icon from '../../../../assets/Icon/icons';
import Lottie from 'lottie-react';
import verifAnimation from './verifyAnimation.json';
import check from './check.json';
import failed from './failed.json';
import {QRCodeSVG} from 'qrcode.react';
import useAuth from '../../../../hooks/useAuth';
import { UserContext } from '../../../../context/UserContext';


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

export const fetchData = async (url, token) => {
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`,
    }
  });
  const data = await response.json();
  return data;
}

const TwoFaModal = ({handleClose, qrUrl}) => {
  const [otp, setOtp] = useState(['', '', '', '', '', '']);
  const [verificationStatus, setVerificationStatus] = useState('idle');
  const {auth} = useAuth();
  const inputRefs = useRef([]);
  const [qrCode, setQrCode] = useState('');
  const { userData , updateUserData } = useContext(UserContext);

  console.log('qrUrl: ', qrUrl);

  useEffect(() => {
    inputRefs.current[0].focus();
  }, []);

  useEffect(() => {
    setVerificationStatus('loading');
    const fetchQrCode = async () => {
      try {
        const response = await fetch(`${BACKEND_URL}/auth/${qrUrl}`, {
          method: 'GET',
          headers: {
            'Authorization': `Bearer ${auth.accessToken}`
          }
        });
        if(response.ok) {
          const qrCode = await response.blob();
          setQrCode(URL.createObjectURL(qrCode));
          setVerificationStatus('idle');

        }
      } catch (error) {
        setVerificationStatus('failed');
        console.error('Error fetching qr code: ', error);
      }
    }
    fetchQrCode();
  }, []);

  const veryfyOtp = async (otpCode) => {
    setVerificationStatus('loading');
    try {
      console.log('otpCode: ', otpCode);
      const response = await fetch(`${BACKEND_URL}/auth/enable2fa/`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${auth.accessToken}`
        },
        body: JSON.stringify({otp: otpCode})
      });
      if(response.ok) {
        setVerificationStatus('success');
        try {
          const userData = await fetchData(`${BACKEND_URL}/user/stats/`, auth.accessToken);
          console.log('userData: ', userData);
          updateUserData(userData);
        } catch (error) {
          console.error('Error fetching user data:', error);
        }
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
      veryfyOtp(newOtp.join(''));
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
                  <img src={qrCode} alt="QR Code for 2FA setup" />
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
        <button className="close-button" onClick={handleClose}>
          <Icon name="cancelCircle" className="cancelCircle" />
        </button>
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
                  style={verificationStatus === 'success' ? {outline: '2px solid green'} : {}}
                />
              );
            })}
          </div>
          <button 
            className="setup-button" 
            disabled={otp.some(digit => digit === '')}
            onClick={handleClose}
          >
            Complete Setup
          </button>
        </div>
      </div>
    </div>
  );
};

export default TwoFaModal;

