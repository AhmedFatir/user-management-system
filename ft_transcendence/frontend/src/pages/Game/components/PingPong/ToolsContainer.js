import React, {useState, useEffect} from "react";
import leftArrow from '../../Game-assets/left-arrow.png';
import rightArrow from '../../Game-assets/right-arrow.png';
import sKey from '../../Game-assets/s.png';
import upKey from '../../Game-assets/up.png';
import downKey from '../../Game-assets/down.png';
import wKey from '../../Game-assets/w.png';
import { useTranslation } from 'react-i18next'


const ToolsContainer = ( {className, onPaddleSelect, onKeysSelect}) => {
    const paddleColors = ['#BC4F00', '#036145', '#8D0202', '#002194'];
    const [currentColorIndex, setCurrentColorIndex] = useState(0);
    const { t } = useTranslation();
    const [selectedOption, setSelectedOption] = useState(null);

    // useEffect(() => {
    //     // This is correct
    //     console.log('Selected keys changed:', selectedOption);
    //   }, [setSelectedOption]);
    
    const handleSelectOption = (option) => {
        setSelectedOption(option);
        onKeysSelect(option);
    };

    return (
        <div className={className}>
            <div className="keys-container">
                <h1 className="keys-title">{t('Keys')}</h1>
                <div className="keys-selection">
                    <div className={`ws-container container ${selectedOption === 'ws' ? 'selectedOption' : ''}`} onClick={() => handleSelectOption('ws')}>
                        <img src={wKey} alt="" className='key' />
                        <img src={sKey} alt="" className='key' />
                    </div>
                    <div className={`up-down-container container ${selectedOption === 'up-down' ? 'selectedOption' : ''}`} onClick={() => handleSelectOption('up-down')}>
                        <img src={upKey} alt="" className='key' />
                        <img src={downKey} alt="" className='key' />
                    </div>
                </div>
            </div>
        </div>
    );
}
 
export default ToolsContainer;