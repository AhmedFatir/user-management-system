import React, { useContext, useState } from 'react';
import Style from './Setting.module.css';
import AvatarSelect from './components/AvatarSelect/AvatarSelect';
import SettingInput from './components/SettingInput/SettingInput';
import { ToastContainer, toast } from 'react-toastify';
import 'react-toastify/dist/ReactToastify.css';
import useAuth from '../../hooks/useAuth';
import axios from '../../api/axios';
import { SuccessToast } from '../../components/ReactToastify/SuccessToast';
import { ErrorToast } from '../../components/ReactToastify/ErrorToast';
import MainButton from '../../components/MainButton/MainButton';
import { UserContext } from '../../context/UserContext';
import TwoFaModal from './components/TwoFaModal/TwoFaModal';
import {fetchData} from './components/TwoFaModal/TwoFaModal'
import { useTranslation } from 'react-i18next'


const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const SETTING_ENDPOINT = `${BACKEND_URL}/auth/user/me/`

const fetchQrCodeUrl = async (token) => {
  const response = await fetch(`${BACKEND_URL}/auth/enable2fa/`, {
    method: 'GET',
    headers: {
      authorization: `Bearer ${token}`
    }
  });

  const data = await response.json();
  return data;
}


const Setting = () => {
  const { auth }  = useAuth();
  const [activeAvatar, setActiveAvatar] = useState(null);
  const [avatarFile, setAvatarFile] = useState(null);
  const { userData , updateUserData } = useContext(UserContext);
  const [showTwoFaModal, setShowTwoFaModal] = useState(false);
  const [qrCodeUrl, setQrCodeUrl] = useState(null);
  const { t } = useTranslation();


  const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

  const toggleTwoFaModal = async () => {
    const data = await fetchQrCodeUrl(auth.accessToken);
    setQrCodeUrl(data.otp_uri);
    setShowTwoFaModal(true);
  }
  
  const disableTwoFa = async () => {
    const response = await fetch(`${BACKEND_URL}/auth/disable2fa/`, {
      method: 'DELETE',
      headers: {
        authorization: `Bearer ${auth.accessToken}`
      }
    });
    if (response.ok) {
      // SuccessToast('Profile updated successfully!');
      const userData = await fetchData(`${BACKEND_URL}/user/stats/`, auth.accessToken);
      updateUserData(userData);
    }
    else {
      ErrorToast('Failed to update settings. Please try again.');
    }
  }
  
  const closeTwoFaModal = () => {
    disableTwoFa();
    setShowTwoFaModal(false);
  }

  const [updatedvalues, setUpdatedvalues] = useState({
    username : "",
    email : "",
    old_password : "",
    new_password : "",
  });

  const handleFormSubmit = async (e) => {
    e.preventDefault();
    const formData = new FormData();
    
    for (const key in updatedvalues) {
        if (updatedvalues[key] !== "") {
            formData.append(key, updatedvalues[key]);
        }
    }
    if (avatarFile) {
        formData.append('avatar', avatarFile);
    } else if (activeAvatar) {
        formData.append('avatar_type', activeAvatar);
    }
    
    try {
        await axios.patch(SETTING_ENDPOINT, formData, {
            headers: {
                'Content-Type': 'multipart/form-data',
                'Authorization': `Bearer ${auth.accessToken}`,
            }
        });
        const response = await axios.get(`${BACKEND_URL}/user/stats/`, {
            headers: {
                'Authorization': `Bearer ${auth.accessToken}`,
            }
        });
        updateUserData(response.data);
        SuccessToast('Profile updated successfully!');
    } catch (e) {
        ErrorToast('Failed to update settings. Please try again.');
    }
  };

  const handleInputChange = (e) => {
    setUpdatedvalues({ ...updatedvalues, [e.target.name]: e.target.value });
  };

  return (
    <>
      <div className={Style.SettingContainer}>
        <h1>{t('Settings')}</h1>
        <div className={Style.AvatarContainer}>
          <div className={Style.SettingInfo}>
            <h3>{t('Profile Picture')}</h3>
            <p>{t('Update your information about you and details here')}</p>
          </div>
          <div className={Style.Avatars}>
            <AvatarSelect setActiveAvatar={setActiveAvatar} setAvatarFile={setAvatarFile} activeAvatar={activeAvatar} avatarFile={avatarFile}/>
          </div>
        </div>
        <form className={Style.form} onSubmit={handleFormSubmit}>
          <div className={Style.SettingSep}>
          </div>
          <div className={Style.SettingSection}>
            <div className={Style.SettingInfo}>
              <h3>{t('Personal Information')}</h3>
              <p>{t('Update your information about you and details here')}</p>
            </div>
            <div className={Style.InputSection}>
              <SettingInput label={t('User Name')} name='username' placeholder='Perdoxii_noyat' type='text' onChange={handleInputChange} disabled={false}/>
              <SettingInput label={t('Email')} name='email' placeholder='perdoxi@admin.com' type='email' onChange={handleInputChange} disabled={false}/>
            </div>
          </div>
          <div className={Style.SettingSep}></div>
          <div className={Style.SettingSection}>
            <div className={Style.SettingInfo}>
              <h3>{t('Security')}</h3>
              <p>{t('Update your information about you and details here')}</p>
            </div>
            <div className={Style.InputSection}>
              <SettingInput label={t('Current Password')}  name="old_password" placeholder='********************' type='password' onChange={handleInputChange} disabled={userData.api_42_id === null ? false : true}/>
              <SettingInput label={t('New Password')} name="new_password" placeholder='********************' type='password' onChange={handleInputChange} disabled={userData.api_42_id === null ? false : true}/>
            </div>
          </div>
          <div className={Style.SettingSep}></div>
          <div className={Style.TwoFactorContainer}>
            <div className={Style.SettingInfo}>
            <h3>
            {t('Two-factor Authenticator App')}{' '}
            {userData.is_2fa_enabled ? (
              <span style={{ backgroundColor: 'green', color: 'white', padding: '2px 6px', borderRadius: '4px', fontSize: '13px'}}>{t('Enabled')}</span>) 
              : 
              (<span style={{ backgroundColor: 'red', color: 'white', padding: '2px 6px', borderRadius: '4px', fontSize: '13px' }}>{t('Disabled')}</span>)
            }
            </h3>
              <p>{t("Use an Authenticator App as your two-factor authentication (2FA). When you sign in you'll be asked to use the security code provided by your Authenticator.")}</p>
            </div>
            {!userData.is_2fa_enabled ? (<button type="button" onClick={toggleTwoFaModal} className={Style.twoFaButton}>{t('Enable')}</button> ) 
            : 
            (<button type="button" onClick={disableTwoFa} className={Style.twoFaButton}>{t('Disable')}</button> )}
            {showTwoFaModal && <TwoFaModal handleClose={closeTwoFaModal} qrUrl={qrCodeUrl}/>}
          </div>
          <MainButton type="submit" onClick={handleFormSubmit} content="Update"/>
        </form>
      </div> 
    </>
  );
}

export default Setting;







