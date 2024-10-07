import React, { useState, useEffect, useContext } from 'react';
import useAuth from '../../../hooks/useAuth';
import Icon from '../../../assets/Icon/icons';
import { InfoToast } from '../../../components/ReactToastify/InfoToast';
import { ErrorToast } from '../../../components/ReactToastify/ErrorToast';
import { SuccessToast } from '../../../components/ReactToastify/SuccessToast';
import { UserContext } from '../../../context/UserContext';
import { ProfileContext } from '../../../context/ProfilContext';
import { useTranslation } from 'react-i18next';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;



const BlockUnblockButton = ({ blockedId }) => {

    const {profilisBlocked, setIsBlocked,isBlockingHim,isBlockedMe,setIsBlocking,setIsRequst} = useContext(ProfileContext)
    const {updateBlockedList} = useContext(UserContext)
    const { auth }  = useAuth()
    const { t } = useTranslation();


    const handleBlockUnblock = async () => {
        const url = `${BACKEND_URL}/user/${blockedId}/block-unblock/`;
        try {
            const response = await fetch(url, {
                method: profilisBlocked ? 'DELETE' : 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                },
            });

            if (response.ok) {
                setIsBlocked(!profilisBlocked);
                setIsBlocking(!isBlockingHim);
                setIsRequst('Friend request does not exist.')
                SuccessToast(`User has been ${profilisBlocked ? 'unblocked' : 'blocked'} successfully.`);
                const BlockedResponse = await fetch(`${BACKEND_URL}/user/block-unblock/`, {
                    method: 'GET',
                        headers: {
                          'Content-Type': 'application/json',
                          'Authorization': `Bearer ${auth.accessToken}`
                        }
                      });
                      
                      if (!BlockedResponse.ok) {
                        throw new Error('Network response was not ok');
                      }
                      
                      const newBlockedList = await BlockedResponse.json();
                      updateBlockedList(newBlockedList);

            } else {
                const data = await response.json();
                ErrorToast(data.error || 'An error occurred.');
    
            }
        } catch (error) {
            console.error(`Error ${profilisBlocked ? 'unblocking' : 'blocking'} user:`, error);
            ErrorToast('An error occurred.');
    
        }
    };


    return (
        <div className={`BlockFriend-button profil-button ${isBlockedMe ? 'disabled' : ''}`} onClick={handleBlockUnblock}>
            <Icon name="BlockFriend" className='Block-Friend profil-icon' />
            <p>{profilisBlocked ? t('Unblock') : t('Block')}</p>

        </div>
    );
};

export default BlockUnblockButton;
