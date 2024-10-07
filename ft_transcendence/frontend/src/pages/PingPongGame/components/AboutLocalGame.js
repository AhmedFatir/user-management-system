import React, { useState, useEffect } from "react";
import "./aboutlocalgame.css"
import "./gameInfo.css"
import avatar1 from "../../../assets/avatar1.png"
import avatar2 from "../../../assets/avatar2.png"
import { useTranslation } from 'react-i18next'

const AboutLocalGame = ({player1, player2, handleStartGame}) => {
    const [timer, setTimer] = useState(7);
    const { t } = useTranslation();

    const rules = {
        1: t("1- Victory Condition: The game is won by the first player to score 11 points."),
        2: t("2- Paddle Movement: Control your paddle using the keys you've chosen:"),
        3: <>   • <span className="player-name">{player1?.username}</span> {t("W to move up, S to move down.")}</>,
        4: <>   • <span className="player-name">{player2?.username}</span> {t("Arrow Up to move up, Arrow Down to move down.")}</>,
        5: t("3- Stay Focused: You're in a fierce competition—keep your cool and don't lose!"),
        6: t("4- This is local game, so no match history will be saved, and no XP will be updated"),
    };

    useEffect(() => {
        if (timer === 0) {
            handleStartGame();
            return;
        }

        const interval = setInterval(() => {
            setTimer(prev => prev - 1);
        }, 1000);

        return () => clearInterval(interval);
    }, [timer, handleStartGame]);

    return (
        <div className="about-local-game-container">
            <div className="local-players">
                <div className="player">
                    <img src={avatar1} alt={player1?.username || "Player 1"} className="player-avatar"/>
                    <h1 className="player-username">{player1?.username}</h1>
                </div>
                <h1 className="timer">{timer}</h1>
                <div className="player">
                    <img src={avatar2} alt={player2?.username || "Player 2"} className="player-avatar"/>
                    <h1 className="player-username">{player2?.username}</h1>
                </div>
            </div>
            <div className="game-info-container">
                <h1 className="game-info-title">{t('ABOUT THE GAME')}</h1>
                <ul className="rules-container">
                    {Object.values(rules).map((rule, index) => (
                        <li key={index} className="rule-item">
                            {React.isValidElement(rule) ? rule : t(rule)}
                        </li>
                    ))}
                </ul>
            </div>
        </div>
    );
}
 
export default AboutLocalGame;