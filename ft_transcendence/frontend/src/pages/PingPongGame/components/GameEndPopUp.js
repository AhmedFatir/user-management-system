import React from 'react';
import './game-end-pop-up.css';
import { useTranslation } from 'react-i18next'


const GameEndPopup = ({ winner, loser, onClose }) => {
  const { t } = useTranslation();

    return (
        <div className="popup-container">
            <div className="popup-content">
                <h2>{t('Game Over')}</h2>
                <p>{t('Winner')}: {winner}</p>
                <p>{t('Loser')}: {loser}</p>
                <button onClick={onClose}>{t('Close')}</button>
            </div>
        </div>
    );
};

export default GameEndPopup;
