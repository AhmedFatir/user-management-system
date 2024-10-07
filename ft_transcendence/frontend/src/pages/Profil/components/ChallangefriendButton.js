import React, { useState, useEffect, useContext } from 'react';
import Icon from '../../../assets/Icon/icons';
import { ProfileContext } from '../../../context/ProfilContext';
import { useTranslation } from 'react-i18next';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import useAuth from '../../../hooks/useAuth';
import { createSendInvitationHandler } from '../../../tools/createSendInvitationHandler';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const ChallangefriendButton = () => {
  const {auth} = useAuth()
  const navigate = useNavigate()
  const {isBlockedMe, isBlockingHim, profilData} = useContext(ProfileContext);
  const { t } = useTranslation();
  const handleSendInvitation = createSendInvitationHandler(auth);
  const isDisabled = isBlockingHim || isBlockedMe;

    const handleChallenge = async () => {
      try {
        await handleSendInvitation(profilData.user_id);
        navigate('/invite-game', { replace:true })
      } catch (error) {
        console.log(error);
      }
    };
    
    return (
        <div onClick={handleChallenge}  className={`Challangefriend-button profil-button ${isDisabled ? 'disabled' : ''}`}>
            <Icon name='Challangefriend' className='Challange-friend profil-icon' />
            <p>{t('Challenge')}</p>        
        </div>
    );
};

export default ChallangefriendButton;