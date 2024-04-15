// InvoiceButton.js
import * as React from 'react';
import Button from '@mui/material/Button';
import { useMutation } from 'react-admin';

const CreateInvoiceButton = ({ record }) => {
    const [mutate] = useMutation();

    const handleClick = () => {
        mutate(
            {
                type: 'create-invoice',
                resource: 'orders',
                payload: { id: record.id },
            },
            {
                onSuccess: () => {
                    alert('Invoice created successfully');
                },
                onFailure: () => {
                    alert('Failed to create invoice');
                },
            }
        );
    };

    return <Button onClick={handleClick}>Create Invoice</Button>;
};

export default CreateInvoiceButton;
