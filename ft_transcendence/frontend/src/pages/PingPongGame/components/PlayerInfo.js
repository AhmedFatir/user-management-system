import React, { useEffect, useState } from 'react';
import './playerInfo.css';
import vs from '../asstes/VS.png';
import GameInfo from './GameInfo';
import { useTranslation } from 'react-i18next'

const BACKEND_URL = process.env.REACT_APP_BACKEND_URL;

const PlayerInfo = ({ player1, player2, onStartGame}) => {
    const [timer, setTimer] = useState(7);
    const [isGameStarting, setIsGameStarting] = useState(false);
    const { t } = useTranslation();


    useEffect(() => {
        if (timer === 0) {
            setIsGameStarting(true);
            onStartGame(true);
            return;
        }

        const interval = setInterval(() => {
            setTimer(prev => prev - 1);
        }, 1000);

        return () => clearInterval(interval);
    }, [timer]);
    if (!player1 || !player2) {
        return <div><h1>{t('Loading...')}</h1></div>;
    }
    return (
        <div className="player-info-container">
            {!isGameStarting && (
                <>
                    <h1 className='vs-image'>{timer}</h1>
                    <div className='player-container'>
                        <div className="player-img-container">
                            <img src={`${BACKEND_URL}${player1.avatar}`} alt="PlayerAvatar" className='player-avatar'/>
                            <h1 className='player-username'>{player1.username}</h1>
                        </div>
                        <div className="players-informations">
                            <div className="info">
                                <div className="data">
                                    <h2>{player1.rank}</h2>
                                </div>
                                <div className="title-container">
                                    <h2>{t('RANK')}</h2>
                                </div>
                                <div className="data">
                                    <h2>{player2.rank}</h2>
                                </div>
                            </div>
                            <div className="info">
                                <div className="data">
                                    <h2>{player1.games_played}</h2>
                                </div>
                                <div className="title-container">
                                    <h2>{t('GAMES PLAYED')}</h2>
                                </div>
                                <div className="data">
                                    <h2>{player2.games_played}</h2>
                                </div>
                            </div>
                            <div className="info">
                                <div className="data">
                                    <h2>0</h2>
                                </div>
                                <div className="title-container">
                                    <h2>{t('WIN RATE')}</h2>
                                </div>
                                <div className="data">
                                    <h2>0</h2>
                                </div>
                            </div>
                        </div>
                        <div className="player-img-container">
                            <img src={`${BACKEND_URL}${player2.avatar}`} alt="PlayerAvatar" className='player-avatar'/>
                            <h1 className='player-username'>{player2.username}</h1>
                        </div>
                    </div>
                    {/* <div className="timer-container">
                        <h2>Starting in: {timer}s</h2>
                    </div> */}
                <GameInfo/>
                </>
            )}
        </div>
    );
}

export default PlayerInfo;
