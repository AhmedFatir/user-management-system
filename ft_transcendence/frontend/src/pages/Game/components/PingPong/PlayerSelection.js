import React, { useEffect, useRef } from 'react';
import useFetch from '../../../../hooks/useFetch';
import useAuth from '../../../../hooks/useAuth';
import players from '../../Data';
import defit from '../../Game-assets/defit.png';
import axios from 'axios';
import { useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next'
import { createSendInvitationHandler } from '../../../../tools/createSendInvitationHandler';

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;
const WS_BACKEND_URL = process.env.REACT_APP_WS_BACKEND_URL;

const PlayerSelection = ({ onPlayerSelect, onCancel }) => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const { auth } = useAuth();
  const { data, isLoading, error } = useFetch(`${BACKEND_URL}/user/friends/list/`);
  const ws = useRef(null);
  const handleSendInvitation = createSendInvitationHandler(auth);

  // useEffect(() => {
  //   ws.current = new WebSocket(`${WS_BACKEND_URL}/ws/notifications/?token=${auth.accessToken}`);
  //   ws.current.onopen = () => {
  //     console.log('WebSocket connection established');
  //   };
  //   ws.current.onclose = () => {
  //     console.log('WebSocket connection closed');
  //   };

  //   return () => {
  //     if (ws.current) {
  //       ws.current.close();
  //     }
  //   };
  // }, []);

  const handleChallenge = async (player) => {
    try {
      await handleSendInvitation(player.id);
      navigate('/invite-game', { replace:true })
    } catch (error) {
      console.log(error);
    }
  };

  return (
    <div className="player-selection-overlay">
      <div className="player-selection">
        <h2>{t('ONLINE FRIENDS')}</h2>
        <ul>
          {data && data.map(player => (
            <li key={player.id} className='player-item'>
              <div className='player-info'>
                <img src={`${BACKEND_URL}${player.avatar}`} alt={player.username} className='player-image' />
                <p className='player-name'>{player.username}</p>
              </div>
              <button className='player-challenge' onClick={() => handleChallenge(player)}>{t('INVITE')}</button>
            </li>
          ))}
        </ul>
        <button onClick={onCancel} className='cancel'>{t('Cancel')}</button>
      </div>
    </div>
  );
};

export default PlayerSelection;
