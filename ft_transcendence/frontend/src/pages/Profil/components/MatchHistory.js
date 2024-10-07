import React from 'react'
import { useState, useEffect } from 'react'
import useFetch from '../../../hooks/useFetch'
import useAuth from '../../../hooks/useAuth';
import Lottie from 'lottie-react';
import { useNavigate } from 'react-router-dom';   
import { useContext } from 'react';  
import { ProfileContext } from '../../../context/ProfilContext'; 
import History from '../../../assets/MatchHistoryData'
import { useTranslation } from 'react-i18next';
import HistoryItem from './HistoryItem'
import sadFace from '../../../assets/sadFace.json'
import './matchHistory.css'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;


function MatchHistory({profil}) {

  const navigate = useNavigate();
  const { auth }  = useAuth()
  const { t } = useTranslation();
  const {history} = useContext(ProfileContext)


   const handleItemClick = async (history) => {
      let playerId = history.winner_user.user_id;
      if (history.is_winner) {
        playerId = history.loser_user.user_id;
      }
   
   
        const url = `${BACKEND_URL}/user/stats/${playerId}`;
        try {
            const response = await fetch(url, {
                method: 'GET',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${auth.accessToken}`,
                },
            });
            if (response.ok) {
                const dataa = await response.json();
               
                navigate(`/user/${dataa.username}`, {
                  state: { userData: dataa },
                });
            
            } else {
                console.error('Error fetching block status:', response.statusText);
            }
        } catch (error) {
            console.error('Error fetching block status:', error);
        }
    
      };

  return (
    <div className="macthContainer">
    <div className="matchHeader">
      <h2>{t('Match History')}</h2>
    </div>
    <div className="historyCard">
      {history && history.length > 0 ? (
        history.slice().reverse().map((historyItem) => (
          <div key={historyItem.id} onClick={() => handleItemClick(historyItem)}>
            <HistoryItem history={historyItem} />
          </div>
        ))
      ) : (
        <div className='sadFaceAnimationGame'>
              <div className='sadeFaceGame'><Lottie  animationData={sadFace} /> </div>
              <h3>{t('No match history available.')}</h3>
        </div>
      )}
    </div>
  </div>
  )
}

export default MatchHistory