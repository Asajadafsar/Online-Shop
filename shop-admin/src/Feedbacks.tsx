import * as React from 'react';
import {
    List,
    Datagrid,
    TextField,
    NumberField,
    TextInput,
    SearchInput,
    FilterButton,
    TopToolbar,
    CreateButton,
    useListContext,
    Pagination,
    FilterForm,
    ImageField
} from 'react-admin';
import { Stack } from '@mui/material';

const FeedbackFilters = [
    <SearchInput source="rating" alwaysOn />,
    <TextInput label="rating" source="rating" resettable />,
];

const ListToolbar = () => (
    <Stack direction="row" justifyContent="space-between">
        <FilterForm filters={FeedbackFilters} />
        <div>
            <FilterButton filters={FeedbackFilters} />
        </div>
    </Stack>
)

export const FeedbackList = () => (
    <List>
        <ListToolbar />
        <Datagrid rowClick="edit">
            <TextField source="id" label="ID" />
            <TextField source="user_id" label="User ID" />
            <TextField source="order_id" label="Order ID" />
            <TextField source="rating" label="Rating" />
            <TextField source="comment" label="Comment" />
            <TextField source="feedback_date" label="Feedback Date" />
        </Datagrid>
    </List>
);

export default FeedbackList;
