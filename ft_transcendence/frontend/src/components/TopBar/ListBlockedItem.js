import React from 'react'
import { useEffect, useState, useContext } from 'react';
import useFetch from '../../hooks/useFetch';
import useAuth from '../../hooks/useAuth';
import './listBlockedItem.css'
import { ErrorToast } from '../ReactToastify/ErrorToast';
import { SuccessToast } from '../ReactToastify/SuccessToast';
import { InfoToast } from '../ReactToastify/InfoToast';
import { UserContext } from '../../context/UserContext';
import { ProfileContext } from '../../context/ProfilContext';
import { useTranslation } from 'react-i18next'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function ListBlockedItem({user}) {
    const {data ,isLoading, error} = useFetch(`${BACKEND_URL}/user/stats/${user.id}`)
    const [profilData, setProfilData] = useState([]);
    const { auth }  = useAuth()
    const { t } = useTranslation();
    const {updateBlockedList} = useContext(UserContext)
    const {setIsBlocked, profilisBlocked, setIsBlocking, isBlockingHim} = useContext(ProfileContext)

    useEffect(() => {
        if (data) {
        setProfilData(data);
        }
    }, [data]);
 
    const handleUnblock = async () => {
        const url = `${BACKEND_URL}/user/${user.id}/block-unblock/`;
        try {
            const response = await fetch(url, {
                method:'DELETE' ,
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                },
            });

            if (response.ok) {
                setIsBlocked(!profilisBlocked)
                setIsBlocking(!isBlockingHim);
                SuccessToast(`User has been unblocked successfully.`);
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
            console.error(`Error unblocking user:`, error);
            ErrorToast('An error occurred.');
         
        }
    };
    
    return (
        <div className='listBlockerItem'>
            <div className='blockedImageName'>
                <img src={`${BACKEND_URL}${profilData.avatar}`} alt="profil_pic" />
                <div className='blockedName'>
                    {profilData.username}
                </div>
            </div>
            <div className='unblockUserButton' onClick={handleUnblock}>
                <button>{t('Unblock')}</button>
            </div>
        </div>
    )
}

export default ListBlockedItem