import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import axios from '../../api/axios';
import useAuth from '../../hooks/useAuth';
import Lottie from 'lottie-react';
import loadingAnimation from './loading-animation.json';
import './OauthTwo.css'

const AuthTwo = () => {
  const location = useLocation();
  const navigate = useNavigate();
  const { setAuth } = useAuth();
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    console.log("Authentication process started");
    const searchParams = new URLSearchParams(location.search);
    const code = searchParams.get('code');
    console.log("Received code:", code);

    if (code) {
      axios.post("/auth/callback/", { code }, {
        withCredentials: true
      })
      .then(response => {
        const accessToken = response.data['access'];
        const requires2FA = response.data['2fa_required']; 
        const username = response.data['username']; 


        // setAuth({ accessToken });
        console.log("Access token received:", accessToken);

        if (requires2FA) {
            console.log("2FA required, redirecting to 2FA page");
            navigate('/auth', { state: { is2FA: true, accessToken, username } });
        } else {
            console.log("Authentication successful, redirecting to home");
            setAuth({ accessToken });
            navigate('/');
        }
      })
      .catch(error => {
        console.error('Error during authentication', error);
        navigate('/auth');
      })
      .finally(() => {
        setLoading(false);
      });
    } else {
      console.error('No authentication code received');
      setLoading(false);
      navigate('/auth');
    }
  }, [location, navigate, setAuth]);

  return (
    <div className='oauth-loading'>
      {loading && (
        <Lottie animationData={loadingAnimation} style={{ width: 400, height: 400 }} />
      )}
    </div>
  );
}

export default AuthTwo;
